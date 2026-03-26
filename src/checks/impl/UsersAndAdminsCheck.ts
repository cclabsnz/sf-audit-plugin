import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PsaRecord {
  Assignee: { Id: string; Username: string; Name?: string; Profile?: { Name: string } };
  PermissionSet: { Name: string; IsOwnedByProfile?: boolean };
}

export class UsersAndAdminsCheck implements SecurityCheck {
  readonly id = 'users-and-admins';
  readonly name = 'Users and Admins';
  readonly category = 'Users & Admins';
  readonly description = 'Identifies users with dangerous system-wide permissions (ModifyAllData, ViewAllData, AuthorApex, CustomizeApplication)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const userLink = (r: PsaRecord): string => {
      const profile = r.Assignee.Profile?.Name ?? 'Unknown Profile';
      return `[${r.Assignee.Username} (${profile})](${baseUrl}/${r.Assignee.Id})`;
    };

    // Total active users
    const activeUsersResult = await ctx.soql.query<{ expr0: number }>(
      'SELECT COUNT() FROM User WHERE IsActive = true'
    );
    const totalActiveUsers = activeUsersResult.totalSize;

    // Modify All Data
    const modifyAllResult = await ctx.soql.query<PsaRecord>(
      'SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsModifyAllData = true AND Assignee.IsActive = true'
    );
    const modifyAllUsers = modifyAllResult.records;
    const modifyAllCount = modifyAllUsers.length;

    const modifyRisk = modifyAllCount > 5 ? 'CRITICAL' : modifyAllCount > 3 ? 'HIGH' : 'LOW';
    findings.push({
      id: 'users-modify-all-data',
      category: this.category,
      riskLevel: modifyRisk,
      title: `${modifyAllCount} user(s) have Modify All Data permission`,
      detail: 'Modify All Data grants unrestricted write access across all objects. This is one of the most powerful permissions in Salesforce.',
      remediation: 'Limit Modify All Data to essential system administrators only. Review each user and remove the permission from any non-essential accounts.',
      affectedItems: modifyAllUsers.map(userLink),
    });

    // View All Data
    const viewAllResult = await ctx.soql.query<PsaRecord>(
      'SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsViewAllData = true AND Assignee.IsActive = true'
    );
    const viewAllUsers = viewAllResult.records;
    const viewAllCount = viewAllUsers.length;

    const viewRisk = viewAllCount > 10 ? 'HIGH' : viewAllCount > 5 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'users-view-all-data',
      category: this.category,
      riskLevel: viewRisk,
      title: `${viewAllCount} user(s) have View All Data permission`,
      detail: 'View All Data grants unrestricted read access across all objects, bypassing sharing rules and record-level security.',
      remediation: 'Limit View All Data to essential users. Consider using permission sets scoped to specific objects instead.',
      affectedItems: viewAllUsers.map(userLink),
    });

    // Customize Application
    const customizeAppResult = await ctx.soql.query<PsaRecord>(
      'SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsCustomizeApplication = true AND Assignee.IsActive = true'
    );
    const customizeAppUsers = customizeAppResult.records;
    const customizeAppCount = customizeAppUsers.length;

    if (customizeAppCount > 5) {
      findings.push({
        id: 'users-customize-application',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${customizeAppCount} user(s) have Customize Application permission`,
        detail: 'Customize Application allows users to make metadata changes, including modifying page layouts, custom fields, and application settings.',
        remediation: 'Customize Application allows metadata changes. Review and reduce to essential configuration administrators.',
        affectedItems: customizeAppUsers.map(userLink),
      });
    }

    // Author Apex
    const authorApexResult = await ctx.soql.query<PsaRecord>(
      'SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name FROM PermissionSetAssignment WHERE PermissionSet.PermissionsAuthorApex = true AND Assignee.IsActive = true'
    );
    const authorApexUsers = authorApexResult.records;
    const authorApexCount = authorApexUsers.length;

    if (authorApexCount > 3) {
      findings.push({
        id: 'users-author-apex',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${authorApexCount} user(s) have Author Apex permission`,
        detail: 'Author Apex allows users to write and deploy Apex code, which can execute server-side logic with elevated privileges.',
        remediation: 'Author Apex allows code deployment. Limit to developers with a genuine need.',
        affectedItems: authorApexUsers.map(userLink),
      });
    }

    return {
      findings,
      metrics: {
        totalActiveUsers,
        modifyAllDataUsersCount: modifyAllCount,
        viewAllDataUsersCount: viewAllCount,
      },
    };
  }
}
