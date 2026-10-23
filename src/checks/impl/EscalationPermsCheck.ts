import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { presentFields } from '../support/schema.js';

interface AssignmentRecord {
  AssigneeId: string;
  Assignee: { Username: string };
  PermissionSet: {
    PermissionsManageInternalUsers: boolean;
    PermissionsAssignPermissionSets: boolean;
    PermissionsModifyMetadata: boolean;
    PermissionsManageAuthProviders: boolean;
    PermissionsManageConnectedApps: boolean;
    PermissionsManageSessionPermissionSets: boolean;
    PermissionsPasswordNeverExpires: boolean;
    PermissionsViewAllUsers: boolean;
  };
}

// Hygiene, not escalation: they weaken a credential or widen visibility, but give no way to grant
// oneself more access. Reported apart so they never stand in for an escalation path. RULE-077.
const HYGIENE = new Set(['Password Never Expires', 'View All Users']);

const PERMS: Array<[keyof AssignmentRecord['PermissionSet'], string]> = [
  ['PermissionsManageInternalUsers', 'Manage Internal Users'],
  ['PermissionsAssignPermissionSets', 'Assign Permission Sets'],
  ['PermissionsModifyMetadata', 'Modify Metadata'],
  ['PermissionsManageAuthProviders', 'Manage Auth. Providers'],
  ['PermissionsManageConnectedApps', 'Manage Connected Apps'],
  ['PermissionsManageSessionPermissionSets', 'Manage Session Permission Set Activations'],
  ['PermissionsPasswordNeverExpires', 'Password Never Expires'],
  ['PermissionsViewAllUsers', 'View All Users'],
];

export class EscalationPermsCheck implements SecurityCheck {
  readonly id = 'escalation-perms';
  readonly name = 'Privilege Escalation Permissions';
  readonly category = 'Permissions';
  readonly description =
    'Flags users holding lateral-movement/persistence permissions (Manage Internal Users, Assign Permission Sets, Modify Metadata, Manage Auth Providers, etc.)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let rows: AssignmentRecord[];
    // Manage Connected Apps and similar exist only in some orgs; one absent field fails the whole
    // query. Select only those this org has: a permission it lacks cannot be held.
    let perms = PERMS;
    try {
      const present = new Set(await presentFields(ctx, 'PermissionSet', PERMS.map(([f]) => f)));
      perms = PERMS.filter(([f]) => present.has(f));
      const permFields = perms.map(([f]) => `PermissionSet.${f}`).join(', ');
      const permWhere = perms.map(([f]) => `PermissionSet.${f} = true`).join(' OR ');
      rows = await ctx.soql.queryAll<AssignmentRecord>(
        `SELECT AssigneeId, Assignee.Username, ${permFields}
         FROM PermissionSetAssignment
         WHERE (${permWhere}) AND Assignee.IsActive = true`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'escalation-perms-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Privilege-escalation permission check could not be completed',
        detail: `Who holds escalation permissions could not be read, so this is unassessed. The org said: ${msg}`,
        remediation: 'Check the error above. If it is an access error, confirm the audit user has "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    // A super-admin (Modify All Data + View All Data + Manage Users) already has unrestricted control,
    // rated by users-super-admin-combo. Escalation permissions matter on everyone else. RULE-077.
    let superAdmins = new Set<string>();
    try {
      superAdmins = await this.superAdminIds(ctx);
    } catch {
      // Without the super-admin list, keep every holder: over-reporting beats hiding a holder.
    }

    const affected: Array<{ username: string; userId: string; perm: string }> = [];
    let leftOut = 0;
    for (const row of rows) {
      if (superAdmins.has(row.AssigneeId)) {
        if (perms.some(([field]) => row.PermissionSet[field])) leftOut++;
        continue;
      }
      for (const [field, label] of perms) {
        if (row.PermissionSet[field]) {
          affected.push({ username: row.Assignee?.Username ?? row.AssigneeId, userId: row.AssigneeId, perm: label });
        }
      }
    }

    if (affected.length === 0) {
      findings.push({
        id: 'escalation-perms-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: leftOut > 0 ? 'Only super-admins hold privilege-escalation permissions' : 'No users hold privilege-escalation permissions',
        detail:
          leftOut > 0
            ? 'Escalation permissions are held only by super-admins, who already have unrestricted control and are rated in the super-admin finding (users-super-admin-combo).'
            : 'No active users were found holding lateral-movement or persistence permissions.',
        remediation: 'Continue to review escalation permissions periodically.',
      });
      return { findings };
    }

    const leftOutNote =
      leftOut > 0
        ? ` ${new Set(rows.filter((r) => superAdmins.has(r.AssigneeId)).map((r) => r.AssigneeId)).size} super-admin(s) also hold them and are rated in the super-admin finding instead.`
        : '';
    const item = (a: { username: string; userId: string; perm: string }) => ({
      label: `${a.username}: ${a.perm}`,
      url: `${baseUrl}/${a.userId}`,
      note: 'Review and remove if not essential',
    });
    const escalation = affected.filter((a) => !HYGIENE.has(a.perm));
    const hygiene = affected.filter((a) => HYGIENE.has(a.perm));

    if (escalation.length > 0) {
      findings.push({
        id: 'escalation-perms-found',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${escalation.length} escalation-permission grant(s) across active users`,
        detail:
          'These permissions let a user create accounts, reset passwords, assign permission sets, modify metadata, ' +
          'or register auth providers: the primitives an attacker uses for lateral movement and persistence after an initial foothold.' +
          leftOutNote,
        remediation:
          'Remove these permissions from non-administrator profiles/permission sets and document who legitimately needs each one.',
        affectedItems: escalation.map(item),
      });
    }

    if (hygiene.length > 0) {
      findings.push({
        id: 'escalation-perms-hygiene',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${hygiene.length} grant(s) of Password Never Expires or View All Users to non-administrators`,
        detail:
          'Password Never Expires keeps a leaked password valid indefinitely; View All Users exposes the full user roster for targeting. ' +
          'Neither lets a user grant themselves more access.' +
          leftOutNote,
        remediation: 'Limit these to service accounts and administrators that need them, and document each.',
        affectedItems: hygiene.map(item),
      });
    }

    return { findings };
  }

  /** Active, unfrozen users holding Modify All Data, View All Data and Manage Users across their assignments. */
  private async superAdminIds(ctx: AuditContext): Promise<Set<string>> {
    const rows = await ctx.soql.queryAll<{
      AssigneeId: string;
      PermissionSet: { PermissionsModifyAllData: boolean; PermissionsViewAllData: boolean; PermissionsManageUsers: boolean };
    }>(
      `SELECT AssigneeId, PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData, PermissionSet.PermissionsManageUsers
       FROM PermissionSetAssignment
       WHERE (PermissionSet.PermissionsModifyAllData = true OR PermissionSet.PermissionsViewAllData = true OR PermissionSet.PermissionsManageUsers = true)
         AND Assignee.IsActive = true`,
    );
    const held = new Map<string, Set<string>>();
    for (const r of rows) {
      const s = held.get(r.AssigneeId) ?? new Set<string>();
      if (r.PermissionSet.PermissionsModifyAllData) s.add('mad');
      if (r.PermissionSet.PermissionsViewAllData) s.add('vad');
      if (r.PermissionSet.PermissionsManageUsers) s.add('mu');
      held.set(r.AssigneeId, s);
    }
    return new Set([...held].filter(([, s]) => s.size === 3).map(([id]) => id));
  }
}
