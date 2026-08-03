import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding, AffectedItem } from '../../findings/Finding.js';

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

    const userItem = (r: PsaRecord): AffectedItem => ({
      label: `${r.Assignee.Username} (${r.Assignee.Profile?.Name ?? 'Unknown Profile'})`,
      url: `${baseUrl}/${r.Assignee.Id}`,
      note: `via: ${r.PermissionSet.IsOwnedByProfile ? 'Profile' : r.PermissionSet.Name}`,
    });

    // Total active, non-frozen users
    const activeUsersResult = await ctx.soql.query<{ expr0: number }>(
      'SELECT COUNT() FROM User WHERE IsActive = true AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
    );
    const totalActiveUsers = activeUsersResult.totalSize;

    // Single query for all broad permissions — avoids multiple round-trips to the org.
    // We filter per-permission in TypeScript after fetching.
    interface BroadPermRecord {
      Assignee: { Id: string; Username: string; Name?: string; Profile?: { Name: string } };
      PermissionSet: {
        Name: string;
        IsOwnedByProfile?: boolean;
        PermissionsModifyAllData: boolean;
        PermissionsViewAllData: boolean;
        PermissionsManageUsers: boolean;
        PermissionsCustomizeApplication: boolean;
        PermissionsAuthorApex: boolean;
      };
    }

    const broadPermResult = await ctx.soql.query<BroadPermRecord>(
      `SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name,
              PermissionSet.Name, PermissionSet.IsOwnedByProfile,
              PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
              PermissionSet.PermissionsManageUsers, PermissionSet.PermissionsCustomizeApplication,
              PermissionSet.PermissionsAuthorApex
       FROM PermissionSetAssignment
       WHERE (PermissionSet.PermissionsModifyAllData = true
           OR PermissionSet.PermissionsViewAllData = true
           OR PermissionSet.PermissionsManageUsers = true
           OR PermissionSet.PermissionsCustomizeApplication = true
           OR PermissionSet.PermissionsAuthorApex = true)
         AND Assignee.IsActive = true
         AND AssigneeId NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`
    );

    const broadPerms = broadPermResult.records;

    // Group by permission — a user may appear multiple times (once per permission set granting them)
    const modifyAllUsers = broadPerms.filter((r) => r.PermissionSet.PermissionsModifyAllData);
    const viewAllUsers   = broadPerms.filter((r) => r.PermissionSet.PermissionsViewAllData);
    const manageUsersRows = broadPerms.filter((r) => r.PermissionSet.PermissionsManageUsers);
    const customizeAppUsers = broadPerms.filter((r) => r.PermissionSet.PermissionsCustomizeApplication);
    const authorApexUsers   = broadPerms.filter((r) => r.PermissionSet.PermissionsAuthorApex);

    // Deduplicate by Assignee.Id for counting unique users
    const uniqueIds = (rows: BroadPermRecord[]) => new Set(rows.map((r) => r.Assignee.Id));
    const modifyAllIds   = uniqueIds(modifyAllUsers);
    const viewAllIds     = uniqueIds(viewAllUsers);
    const manageUsersIds = uniqueIds(manageUsersRows);

    const modifyAllCount   = modifyAllIds.size;
    const viewAllCount     = viewAllIds.size;
    const customizeAppCount = uniqueIds(customizeAppUsers).size;
    const authorApexCount   = uniqueIds(authorApexUsers).size;

    // SBS-ACS-004: flag users with ALL THREE super-admin permissions simultaneously
    const superAdminIds = [...modifyAllIds].filter((id) => viewAllIds.has(id) && manageUsersIds.has(id));
    if (superAdminIds.length > 0) {
      const superAdminItems = superAdminIds.map((id) => {
        const row = modifyAllUsers.find((r) => r.Assignee.Id === id)!;
        return userItem(row as PsaRecord);
      });
      findings.push({
        id: 'users-super-admin-combo',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${superAdminIds.length} user(s) hold the super-admin permission combination (ViewAllData + ModifyAllData + ManageUsers)`,
        detail:
          'SBS-ACS-004 requires documented justification for any user holding all three of ViewAllData, ModifyAllData, and ManageUsers simultaneously. This combination is equivalent to unrestricted org control.',
        remediation:
          'Reduce to the minimum necessary permissions. Document justification for each user in the system of record. Consider breaking this into role-specific permission sets.',
        affectedItems: superAdminItems,
      });
    }

    const modifyRisk = modifyAllCount > 5 ? 'CRITICAL' : modifyAllCount > 3 ? 'HIGH' : 'LOW';
    findings.push({
      id: 'users-modify-all-data',
      category: this.category,
      riskLevel: modifyRisk,
      title: `${modifyAllCount} user(s) have Modify All Data permission`,
      detail: 'Modify All Data grants unrestricted write access across all objects. This is one of the most powerful permissions in Salesforce.',
      remediation: 'Limit Modify All Data to essential system administrators only. Review each user and remove the permission from any non-essential accounts.',
      affectedItems: modifyAllUsers.map((r) => userItem(r as PsaRecord)),
    });

    const viewRisk = viewAllCount > 10 ? 'HIGH' : viewAllCount > 5 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'users-view-all-data',
      category: this.category,
      riskLevel: viewRisk,
      title: `${viewAllCount} user(s) have View All Data permission`,
      detail: 'View All Data grants unrestricted read access across all objects, bypassing sharing rules and record-level security.',
      remediation: 'Limit View All Data to essential users. Consider using permission sets scoped to specific objects instead.',
      affectedItems: viewAllUsers.map((r) => userItem(r as PsaRecord)),
    });

    if (customizeAppCount > 5) {
      findings.push({
        id: 'users-customize-application',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${customizeAppCount} user(s) have Customize Application permission`,
        detail: 'Customize Application allows users to make metadata changes, including modifying page layouts, custom fields, and application settings.',
        remediation: 'Customize Application allows metadata changes. Review and reduce to essential configuration administrators.',
        affectedItems: customizeAppUsers.map((r) => userItem(r as PsaRecord)),
      });
    }

    if (authorApexCount > 3) {
      findings.push({
        id: 'users-author-apex',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${authorApexCount} user(s) have Author Apex permission`,
        detail: 'Author Apex allows users to write and deploy Apex code, which can execute server-side logic with elevated privileges.',
        remediation: 'Author Apex allows code deployment. Limit to developers with a genuine need.',
        affectedItems: authorApexUsers.map((r) => userItem(r as PsaRecord)),
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
