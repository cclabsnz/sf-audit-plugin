import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { EffectivePermissionGrant } from '@cclabsnz/sf-core';
import { DANGEROUS_PERMS } from '../permCatalog.js';

interface PsaRow {
  AssigneeId: string;
  Assignee: { Username?: string; Name?: string; Profile?: { Name?: string } | null } | null;
  PermissionSet: Record<string, boolean> | null;
}

const ADMIN_PROFILE = 'System Administrator';

/** Admin-equivalent = holds Modify All Data, OR can self-escalate to it (Manage Users + Assign Permission Sets). */
function isAdminEquivalent(perms: Set<string>): boolean {
  return perms.has('ModifyAllData') || (perms.has('ManageUsers') && perms.has('AssignPermissionSets'));
}

export class PrivilegedAccessCheck implements SecurityCheck {
  readonly id = 'privileged-access';
  readonly name = 'Privileged Access & Shadow Admins';
  readonly category = 'Permissions';
  readonly description =
    'Resolves each active user\'s effective high-risk permissions (profile + permission sets + groups) and flags admin-equivalent users who are not on the System Administrator profile';

  readonly populatesCache = ['effectivePermissions'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ManageUsers/home`;

    const permFields = DANGEROUS_PERMS.map((p) => `PermissionSet.${p.field}`).join(', ');
    const permWhere = DANGEROUS_PERMS.map((p) => `PermissionSet.${p.field} = true`).join(' OR ');

    let rows: PsaRow[];
    try {
      rows = await ctx.soql.queryAll<PsaRow>(
        `SELECT AssigneeId, Assignee.Username, Assignee.Name, Assignee.Profile.Name, ${permFields}
         FROM PermissionSetAssignment
         WHERE (${permWhere}) AND Assignee.IsActive = true`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'privileged-access-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Effective-permission resolution could not be completed',
        detail: `The PermissionSetAssignment query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration" and "View All Users", then re-run the audit.',
      });
      return { findings };
    }

    // Aggregate per user: a user's effective high-risk permissions are the union across
    // all of their PermissionSetAssignment rows (profile permset + permsets + PSG aggregate).
    const byUser = new Map<string, EffectivePermissionGrant>();
    for (const row of rows) {
      const ps = row.PermissionSet ?? {};
      const held = DANGEROUS_PERMS.filter((p) => ps[p.field]).map((p) => p.key);
      if (held.length === 0) continue;
      let g = byUser.get(row.AssigneeId);
      if (!g) {
        g = {
          userId: row.AssigneeId,
          username: row.Assignee?.Username ?? row.AssigneeId,
          name: row.Assignee?.Name ?? row.Assignee?.Username ?? row.AssigneeId,
          profileName: row.Assignee?.Profile?.Name ?? 'Unknown',
          perms: [],
        };
        byUser.set(row.AssigneeId, g);
      }
      for (const k of held) if (!g.perms.includes(k)) g.perms.push(k);
    }

    const grants = [...byUser.values()];
    ctx.cache.effectivePermissions = grants;

    const shadowAdmins = grants.filter((g) => g.profileName !== ADMIN_PROFILE && isAdminEquivalent(new Set(g.perms)));

    if (shadowAdmins.length > 0) {
      findings.push({
        id: 'privileged-access-shadow-admins',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${shadowAdmins.length} user(s) hold admin-equivalent access without the System Administrator profile`,
        detail:
          'These active users have accumulated effective permissions equivalent to a System Administrator (either "Modify All Data" directly, or "Manage Users" combined with "Assign Permission Sets", which lets them grant themselves anything) but sit on a different profile. Such "shadow admins" are easy to miss in profile-based reviews, yet a takeover of any one grants full org control. The access is reached via the user\'s profile, assigned permission sets, or permission set groups combined.',
        remediation:
          'Review each user\'s permission sets and profile. Remove "Modify All Data" / the Manage Users + Assign Permission Sets pairing unless the role genuinely requires org administration, and consolidate true admins onto a controlled admin profile.',
        affectedItems: shadowAdmins.map((g) => ({
          label: g.username,
          url: setupUrl,
          note: `Profile: ${g.profileName}, effective: ${g.perms.join(', ')}`,
        })),
      });
    } else {
      findings.push({
        id: 'privileged-access-no-shadow-admins',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No shadow admins detected',
        detail:
          'No active user holds admin-equivalent effective permissions outside the System Administrator profile.',
        remediation: 'Continue to keep administrative permissions on a controlled admin profile.',
      });
    }

    // Informational inventory of privileged users (does not affect the grade beyond the above).
    if (grants.length > 0) {
      findings.push({
        id: 'privileged-access-inventory',
        category: this.category,
        riskLevel: 'INFO',
        title: `${grants.length} active user(s) hold at least one high-risk permission`,
        detail:
          'Inventory of active users whose effective permissions include one or more catalogued high-risk permissions. Use this as the privileged-access baseline for least-privilege review.',
        remediation:
          'Periodically confirm each privileged user still requires their high-risk permissions; remove any that are no longer needed.',
        affectedItems: grants
          .slice()
          .sort((a, b) => b.perms.length - a.perms.length)
          .map((g) => ({
            label: g.username,
            url: setupUrl,
            note: `Profile: ${g.profileName}, ${g.perms.length} high-risk perm(s): ${g.perms.join(', ')}`,
          })),
      });
    }

    return { findings };
  }
}
