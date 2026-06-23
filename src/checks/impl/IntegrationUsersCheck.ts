import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface IntegrationUserRecord {
  Id: string;
  Username: string;
  Profile: { Name: string };
  LastLoginDate: string | null;
}

interface BroadPermRecord {
  Assignee: { Id: string; Username: string };
  PermissionSet: {
    Name: string;
    PermissionsModifyAllData: boolean;
    PermissionsViewAllData: boolean;
  };
}

// Username segments that strongly indicate a service/integration account
const SERVICE_LIKE_CLAUSES = [
  "Username LIKE '%service%'",
  "Username LIKE '%integration%'",
  "Username LIKE '%.api@%'",
  "Username LIKE '%_api_%'",
  "Username LIKE '%.svc@%'",
  "Username LIKE '%_svc_%'",
  "Username LIKE '%batch%'",
  "Username LIKE '%automation%'",
  "Username LIKE '%system@%'",
  "Username LIKE '%scheduler%'",
];

const ASSIGNEE_LIKE_CLAUSES = [
  "Assignee.Username LIKE '%service%'",
  "Assignee.Username LIKE '%integration%'",
  "Assignee.Username LIKE '%.api@%'",
  "Assignee.Username LIKE '%_api_%'",
  "Assignee.Username LIKE '%.svc@%'",
];

export class IntegrationUsersCheck implements SecurityCheck {
  readonly id = 'integration-users';
  readonly name = 'Integration / Service Account Inventory';
  readonly category = 'Permissions';
  readonly description = 'SBS-ACS-007/008/009: inventories non-human identities and checks for excess privilege';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Q1: Find candidate service accounts — users who have never logged in (and were created
    // more than 30 days ago, to exclude freshly provisioned human users) or whose username
    // matches common integration account naming patterns. These are likely non-human identities
    // requiring SBS-ACS-007 documentation.
    const serviceUsernameClause = SERVICE_LIKE_CLAUSES.join(' OR ');
    const candidates = await ctx.soql.queryAll<IntegrationUserRecord>(
      `SELECT Id, Username, Profile.Name, LastLoginDate
       FROM User
       WHERE IsActive = true
         AND UserType = 'Standard'
         AND (
           (LastLoginDate = null AND CreatedDate < LAST_N_DAYS:30)
           OR ${serviceUsernameClause}
         )
         AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)
       ORDER BY LastLoginDate ASC NULLS FIRST
       LIMIT 200`
    );

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
        label: u.Username,
        url: `${baseUrl}/${u.Id}`,
        note: u.LastLoginDate
          ? `last login: ${new Date(u.LastLoginDate).toISOString().split('T')[0]} | profile: ${u.Profile.Name}`
          : `never logged in | profile: ${u.Profile.Name}`,
      })),
    });

    // Q2: Among service-account-looking users, find those with Modify All / View All Data.
    // SBS-ACS-008 requires non-human identities to hold only the minimum required permissions.
    const assigneeServiceClause = ASSIGNEE_LIKE_CLAUSES.join(' OR ');
    const broadResult = await ctx.soql.query<BroadPermRecord>(
      `SELECT Assignee.Id, Assignee.Username,
              PermissionSet.Name, PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData
       FROM PermissionSetAssignment
       WHERE Assignee.IsActive = true
         AND Assignee.UserType = 'Standard'
         AND (
           Assignee.LastLoginDate = null
           OR ${assigneeServiceClause}
         )
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
