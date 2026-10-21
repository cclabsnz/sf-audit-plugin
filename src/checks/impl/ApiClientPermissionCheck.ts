import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { hasField } from '../support/schema.js';

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
      // PermissionsUseAnyApiClient is absent from orgs without API Access Control (and from
      // some releases altogether). Describe first: filtering on an absent field is rejected.
      // Absence is unassessed, not a pass: the bypass may exist under a name this check does not read.
      if (!(await hasField(ctx, 'PermissionSet', 'PermissionsUseAnyApiClient'))) {
        findings.push({
          id: 'api-client-permission-not-available',
          category: this.category,
          riskLevel: 'INFO',
          inconclusive: true,
          notAssessed: true,
          title: '"Use Any API Client" holders could not be read: the permission field is not in this org',
          detail:
            'This org has no PermissionSet.PermissionsUseAnyApiClient field, which is usual when API Access Control is not available. Who can bypass API client restrictions is therefore unestablished, and SBS-ACS-006 is unevaluated rather than satisfied.',
          remediation:
            'If API Access Control is enabled, review who holds "Use Any API Client" in Setup → Permission Sets.',
        });
        return { findings };
      }

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
        title: `${users.length} user(s) have the "Use Any API Client" permission: SBS-ACS-006`,
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
    } catch (err) {
      findings.push({
        id: 'api-client-permission-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: '"Use Any API Client" holders could not be read',
        detail:
          `SBS-ACS-006 requires documented justification for the "Use Any API Client" permission. Who holds it could not be read, so this is unassessed. The org said: ${err instanceof Error ? err.message : String(err)}`,
        remediation:
          'Check the error above. If it is an access error, confirm the audit user can read PermissionSetAssignment (View Setup and Configuration); otherwise review assignments in Setup → Permission Sets.',
      });
    }

    return { findings };
  }
}
