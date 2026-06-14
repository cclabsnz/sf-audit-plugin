import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PsaRecord {
  Assignee: { Id: string; Username: string; Profile?: { Name: string } };
  PermissionSet: { Name: string; IsOwnedByProfile?: boolean };
}

export class ApiClientPermissionCheck implements SecurityCheck {
  readonly id = 'api-client-permission';
  readonly name = 'Use Any API Client Permission';
  readonly category = 'Permissions';
  readonly description = 'SBS-ACS-006: flags users with the "Use Any API Client" permission which bypasses API Access Control';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    try {
      // Single query — PermissionsUseAnyApiClient may not exist in orgs without API Access Control
      const result = await ctx.soql.query<PsaRecord>(
        `SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name,
                PermissionSet.Name, PermissionSet.IsOwnedByProfile
         FROM PermissionSetAssignment
         WHERE PermissionSet.PermissionsUseAnyApiClient = true
           AND Assignee.IsActive = true
           AND AssigneeId NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`
      );

      const users = result.records;

      if (users.length === 0) {
        findings.push({
          id: 'api-client-permission-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No users have the "Use Any API Client" permission',
          detail:
            'SBS-ACS-006 requires documented justification for the "Use Any API Client" permission, which bypasses API Access Control restrictions. No active users hold this permission.',
          remediation: 'Continue monitoring as new permission sets are created.',
        });
        return { findings };
      }

      const profileGrantors = users.filter((r) => r.PermissionSet.IsOwnedByProfile);
      findings.push({
        id: 'api-client-permission-assigned',
        category: this.category,
        riskLevel: profileGrantors.length > 0 ? 'HIGH' : 'MEDIUM',
        title: `${users.length} user(s) have the "Use Any API Client" permission — SBS-ACS-006`,
        detail:
          'SBS-ACS-006 requires documented justification for this permission and states it must not be granted to end-users. "Use Any API Client" bypasses API Access Control, allowing the user to connect via any third-party API client regardless of allowed-list restrictions. This significantly expands the attack surface for unauthorised data access.',
        remediation:
          'Review each assignment. Remove from all end-users. Only keep for documented technical users (integration accounts) with a recorded justification in the system of record. Prefer granting through a dedicated permission set, not a profile.',
        affectedItems: users.map((r) => ({
          label: r.Assignee.Username,
          url: `${baseUrl}/${r.Assignee.Id}`,
          note: `via: ${r.PermissionSet.IsOwnedByProfile ? `Profile (${r.Assignee.Profile?.Name ?? 'unknown'})` : r.PermissionSet.Name}`,
        })),
      });
    } catch {
      findings.push({
        id: 'api-client-permission-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: '"Use Any API Client" permission check could not run — field may not exist in this org edition',
        detail:
          'SBS-ACS-006 requires documented justification for the "Use Any API Client" permission. This field is part of the API Access Control feature and may not be available in all Salesforce editions.',
        remediation:
          'Verify in Setup → Permission Sets whether "Use Any API Client" is available and review assignments if so.',
      });
    }

    return { findings };
  }
}
