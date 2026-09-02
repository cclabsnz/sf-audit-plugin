import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { resolveIntegrationAccounts } from '../support/integrationAccounts.js';

interface BroadPermRecord {
  Assignee: { Id: string; Username: string };
  PermissionSet: {
    Name: string;
    PermissionsModifyAllData: boolean;
    PermissionsViewAllData: boolean;
  };
}

export class IntegrationUsersCheck implements SecurityCheck {
  readonly id = 'integration-users';
  readonly name = 'Integration / Service Account Inventory';
  readonly category = 'Permissions';
  readonly description = 'SBS-ACS-007/008/009: inventories non-human identities and checks for excess privilege';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Q1: Resolve candidate integration/service accounts via the shared resolver (Task 2-4),
    // which tags each account with the signal(s) that classified it — integration-license,
    // never-logged-in, username-pattern, scheduled-job-owner, api-only-login — rather than this
    // check keeping its own drifting copy of the username heuristic.
    const resolved = await resolveIntegrationAccounts(ctx);
    if (resolved.unavailable) {
      findings.push({
        id: 'integration-users-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Integration accounts could not be enumerated (insufficient access)',
        detail: 'The audit user could not query User records, so no statement can be made about non-human identities.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run.',
      });
      return { findings };
    }
    const candidates = resolved.accounts;

    if (candidates.length === 0) {
      findings.push({
        id: 'integration-users-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No candidate non-human identities found: SBS-ACS-007',
        detail:
          'SBS-ACS-007 requires all non-human identities to be inventoried and documented. No standard users matching common service account patterns (by username) or never-logged-in users were found.',
        remediation: 'As integration accounts are created, ensure they are documented with a named owner, stated purpose, and review date.',
      });
      return { findings };
    }

    // Inventory finding (INFO) — administrators need this list to comply with SBS-ACS-007
    findings.push({
      id: 'integration-users-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${candidates.length} candidate non-human identity/identities found: SBS-ACS-007`,
      detail:
        'SBS-ACS-007 requires all non-human identities (integration accounts, service users, automation users) to be inventoried and documented with a named owner, stated purpose, and review date. These users were identified by never having a UI login (and being more than 30 days old) or matching common service-account username patterns.',
      remediation:
        'Verify that each listed user is a known, documented non-human identity. Any undocumented account should be reviewed and either documented or deactivated. Maintain a register of all integration identities with their owner and purpose.',
      affectedItems: candidates.map((u) => ({
        label: u.username,
        url: `${baseUrl}/${u.id}`,
        note: u.lastLoginDate
          ? `last login: ${new Date(u.lastLoginDate).toISOString().split('T')[0]} | profile: ${u.profileName}`
          : `never logged in | profile: ${u.profileName}`,
      })),
    });

    // Q2: Among the resolved integration/service accounts, find those with Modify All / View All
    // Data. SBS-ACS-008 requires non-human identities to hold only the minimum required
    // permissions. Filters on the resolver's account ids rather than a username heuristic, so
    // this can never be structurally unable to see an account the inventory above just listed.
    const idList = candidates.map((c) => `'${c.id}'`).join(',');
    const broadResult = await ctx.soql.query<BroadPermRecord>(
      `SELECT Assignee.Id, Assignee.Username,
              PermissionSet.Name, PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData
       FROM PermissionSetAssignment
       WHERE Assignee.IsActive = true
         AND Assignee.UserType = 'Standard'
         AND Assignee.Id IN (${idList})
         AND (PermissionSet.PermissionsModifyAllData = true OR PermissionSet.PermissionsViewAllData = true)
       LIMIT 200`
    );

    const broadPermUsers = broadResult.records;
    if (broadPermUsers.length > 0) {
      const modifyAll = broadPermUsers.filter((r) => r.PermissionSet.PermissionsModifyAllData);
      const viewAll = broadPermUsers.filter(
        (r) => r.PermissionSet.PermissionsViewAllData && !r.PermissionSet.PermissionsModifyAllData
      );

      findings.push({
        id: 'integration-users-broad-permissions',
        category: this.category,
        riskLevel: modifyAll.length > 0 ? 'HIGH' : 'MEDIUM',
        title: `${broadPermUsers.length} service account(s) hold Modify All / View All Data: SBS-ACS-008`,
        detail:
          `SBS-ACS-008 requires non-human identities to hold only the minimum permissions necessary for their function. ${modifyAll.length} account(s) have "Modify All Data" and ${viewAll.length} have "View All Data". These are org-wide permissions exposing all records and should never be granted to integration accounts without explicit documented justification.`,
        remediation:
          `Replace broad data permissions with object- and field-specific permissions scoped to the integration's actual data needs. Use a dedicated permission set that grants only the objects and operations the integration requires.`,
        affectedItems: broadPermUsers.map((r) => ({
          label: r.Assignee.Username,
          url: `${baseUrl}/${r.Assignee.Id}`,
          note: `via: ${r.PermissionSet.Name}: ${r.PermissionSet.PermissionsModifyAllData ? 'Modify All Data' : 'View All Data'}`,
        })),
      });
    }

    return { findings };
  }
}
