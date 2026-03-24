import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PermissionSetRecord { Id: string; Name: string; }

export class PermissionsCheck implements SecurityCheck {
  readonly id = 'permissions';
  readonly name = 'Permissions';
  readonly category = 'Permissions';
  readonly description = 'Reports unassigned permission sets and high profile counts that increase the attack surface';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Permission set count (custom, not owned by profile)
    const psCountResult = await ctx.soql.query<{ expr0: number }>(
      'SELECT COUNT() FROM PermissionSet WHERE IsOwnedByProfile = false'
    );
    const permissionSetCount = psCountResult.totalSize;

    const psRisk = permissionSetCount > 100 ? 'HIGH' : permissionSetCount > 50 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'permissions-set-count',
      category: this.category,
      riskLevel: psRisk,
      title: `${permissionSetCount} custom permission sets in use`,
      detail: 'A large number of permission sets increases administrative complexity and makes it harder to audit access effectively.',
      remediation: 'Review and consolidate permission sets. Excessive numbers increase administrative complexity and expand the attack surface.',
    });

    // Unassigned permission sets
    const unassignedResult = await ctx.soql.query<PermissionSetRecord>(
      'SELECT Id, Name FROM PermissionSet WHERE IsOwnedByProfile = false AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetAssignment)'
    );
    const unassignedSets = unassignedResult.records;
    const unassignedCount = unassignedSets.length;

    if (unassignedCount > 0) {
      findings.push({
        id: 'permissions-unassigned-sets',
        category: this.category,
        riskLevel: 'LOW',
        title: `${unassignedCount} permission set(s) are defined but never assigned`,
        detail: 'Permission sets that are defined but never assigned to any user represent configuration bloat and may indicate outdated or orphaned access configurations.',
        remediation: 'Unused permission sets should be reviewed and deleted to reduce configuration bloat.',
        affectedItems: unassignedSets.map((r) => r.Name),
      });
    }

    // Profile count
    const profileCountResult = await ctx.soql.query<{ expr0: number }>(
      'SELECT COUNT() FROM Profile'
    );
    const profileCount = profileCountResult.totalSize;

    if (profileCount > 30) {
      findings.push({
        id: 'permissions-high-profile-count',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${profileCount} profiles exist in this org`,
        detail: 'A high number of profiles increases the complexity of access management and makes it harder to maintain a clear security model.',
        remediation: 'Consider migrating access control from profiles to permission sets for more granular and auditable access management.',
      });
    }

    return {
      findings,
      metrics: {
        permissionSetCount,
        profileCount,
      },
    };
  }
}
