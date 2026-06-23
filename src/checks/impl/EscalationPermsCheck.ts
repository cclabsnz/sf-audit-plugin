import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AssignmentRecord {
  AssigneeId: string;
  Assignee: { Username: string };
  PermissionSet: {
    PermissionsManageInternalUsers: boolean;
    PermissionsAssignPermissionSets: boolean;
    PermissionsModifyMetadata: boolean;
    PermissionsManageAuthProviders: boolean;
    PermissionsManageConnectedApps: boolean;
    PermissionsManageSession: boolean;
    PermissionsPasswordNeverExpires: boolean;
    PermissionsViewAllUsers: boolean;
  };
}

const PERMS: Array<[keyof AssignmentRecord['PermissionSet'], string]> = [
  ['PermissionsManageInternalUsers', 'Manage Internal Users'],
  ['PermissionsAssignPermissionSets', 'Assign Permission Sets'],
  ['PermissionsModifyMetadata', 'Modify Metadata'],
  ['PermissionsManageAuthProviders', 'Manage Auth. Providers'],
  ['PermissionsManageConnectedApps', 'Manage Connected Apps'],
  ['PermissionsManageSession', 'Manage Session Permission Set Activations'],
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

    const permFields = PERMS.map(([f]) => `PermissionSet.${f}`).join(', ');
    const permWhere = PERMS.map(([f]) => `PermissionSet.${f} = true`).join(' OR ');

    let rows: AssignmentRecord[];
    try {
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
        detail: `The PermissionSetAssignment query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    const affected: Array<{ username: string; userId: string; perm: string }> = [];
    for (const row of rows) {
      for (const [field, label] of PERMS) {
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
        title: 'No users hold privilege-escalation permissions',
        detail: 'No active users were found holding lateral-movement or persistence permissions.',
        remediation: 'Continue to review escalation permissions periodically.',
      });
      return { findings };
    }

    findings.push({
      id: 'escalation-perms-found',
      category: this.category,
      riskLevel: 'HIGH',
      title: `${affected.length} escalation-permission grant(s) across active users`,
      detail:
        'These permissions let a user create accounts, reset passwords, assign permission sets, modify metadata, ' +
        'or register auth providers: the primitives an attacker uses for lateral movement and persistence after an initial foothold.',
      remediation:
        'Remove these permissions from non-administrator profiles/permission sets and document who legitimately needs each one.',
      affectedItems: affected.map((a) => ({
        label: `${a.username}: ${a.perm}`,
        url: `${baseUrl}/${a.userId}`,
        note: 'Review and remove if not essential',
      })),
    });

    return { findings };
  }
}
