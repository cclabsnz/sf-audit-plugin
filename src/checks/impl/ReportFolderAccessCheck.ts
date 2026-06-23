import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FolderRecord {
  Id: string;
  Name: string;
  DeveloperName: string;
  AccessType: string;
}

export class ReportFolderAccessCheck implements SecurityCheck {
  readonly id = 'report-folder-access';
  readonly name = 'Report Folder Public Access';
  readonly category = 'Data Access Control';
  readonly description =
    'Checks for Report folders with Public access: any authenticated user can view all reports and their data';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/o/Report/home`;

    let publicFolders: FolderRecord[];
    try {
      publicFolders = await ctx.soql.queryAll<FolderRecord>(
        `SELECT Id, Name, DeveloperName, AccessType FROM Folder WHERE Type = 'Report' AND AccessType = 'Public'`,
      );
    } catch {
      findings.push({
        id: 'report-folder-access-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Report folder configuration could not be queried',
        detail:
          'The Folder SOQL query was not accessible. This may indicate the audit user lacks access to folder metadata.',
        remediation:
          'Grant "View Setup and Configuration" or "Manage Public Reports" to the audit user and re-run.',
      });
      return { findings };
    }

    if (publicFolders.length === 0) {
      findings.push({
        id: 'report-folder-access-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Report folders have Public access',
        detail:
          'All Report folders are restricted to specific users, roles, or groups. No folder exposes reports to all authenticated users.',
        remediation:
          'Continue reviewing report folder permissions as new reports and folders are created. Ensure sensitive reports are in Private or Shared folders with explicit access grants.',
      });
      return { findings };
    }

    findings.push({
      id: 'report-folder-access-public',
      category: this.category,
      riskLevel: 'HIGH',
      title: `${publicFolders.length} Report folder(s) are publicly accessible to all users`,
      detail:
        `Public Report folders are accessible to every authenticated Salesforce user, including over-permissioned integration accounts, recently activated users, and attackers who have compromised any credential. Reports frequently contain cross-object joins, aggregate data, and sensitive field values that bypass field-level security (FLS does not apply to report results in all configurations). An attacker with basic login access who can open a public report folder can exfiltrate bulk data from Account, Contact, Opportunity, and other sensitive objects by running or exporting the reports inside. This is a common path for mass data exfiltration that bypasses record-level security controls.`,
      remediation:
        'Change Public Report folders to Private or Shared. For Shared folders, explicitly list the users, roles, or groups that need access. Audit the content of public folders to understand the data exposure. Any report in a public folder may have been accessed by any user. Consider enabling Report Snapshot auditing and restricting the "Export Reports" permission for broad user groups.',
      affectedItems: publicFolders.map((f) => ({
        label: f.Name ?? f.DeveloperName ?? f.Id,
        url: setupUrl,
        note: `AccessType: Public. ${publicFolders.length} folder(s) expose reports to all users`,
      })),
    });

    return { findings };
  }
}
