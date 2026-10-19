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

    const psaFrom = `FROM PermissionSetAssignment
       WHERE (PermissionSet.PermissionsModifyAllData = true
           OR PermissionSet.PermissionsViewAllData = true
           OR PermissionSet.PermissionsManageUsers = true
           OR PermissionSet.PermissionsCustomizeApplication = true
           OR PermissionSet.PermissionsAuthorApex = true)
         AND Assignee.IsActive = true
         AND AssigneeId NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`;

    // queryAll fetches every batch, but the client caps how many rows it will fetch and returns the
    // rest silently. The COUNT() says how many rows there are, so a capped read is detected (INT-004).
    const broadPerms = await ctx.soql.queryAll<BroadPermRecord>(
      `SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name,
              PermissionSet.Name, PermissionSet.IsOwnedByProfile,
              PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
              PermissionSet.PermissionsManageUsers, PermissionSet.PermissionsCustomizeApplication,
              PermissionSet.PermissionsAuthorApex
       ${psaFrom}`
    );
    // `partial` means the rows may be incomplete: the COUNT reports more than came back, or the
    // COUNT itself failed, so completeness cannot be confirmed. Counts are then lower bounds.
    let psaTotal: number | undefined;
    try {
      psaTotal = (await ctx.soql.query(`SELECT COUNT() ${psaFrom}`)).totalSize;
    } catch {
      psaTotal = undefined;
    }
    const partial = psaTotal === undefined || psaTotal > broadPerms.length;
    const readNote = psaTotal === undefined
      ? 'whether every assignment was read could not be confirmed'
      : `read ${broadPerms.length} of ${psaTotal} assignments`;
    // "At least N" when the read may be partial: the count is a lower bound, still definite.
    const count = (n: number) => (partial ? `At least ${n}` : `${n}`);

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
        title: `${count(superAdminIds.length)} user(s) hold the super-admin permission combination (ViewAllData + ModifyAllData + ManageUsers)`,
        detail:
          'SBS-ACS-004 requires documented justification for any user holding all three of ViewAllData, ModifyAllData, and ManageUsers simultaneously. This combination is equivalent to unrestricted org control.',
        remediation:
          'Reduce to the minimum necessary permissions. Document justification for each user in the system of record. Consider breaking this into role-specific permission sets.',
        affectedItems: superAdminItems,
      });
    }

    // Every org with an active System Administrator has holders of both permissions, so zero means
    // the assignments were not visible to the audit user, or not all were read. Zero is unknown:
    // inconclusive, never a pass and never an active exposure (INT-004). A non-zero count from a
    // partial read is a definite lower bound, so it stays active at that bound's severity.
    const modifyUnknown = modifyAllCount === 0;
    const viewUnknown = viewAllCount === 0;
    const unknownTitle = (perm: string) => partial
      ? `Could not confirm who holds ${perm}: ${readNote}`
      : `Could not confirm who holds ${perm}`;
    const unknownDetail = (perm: string) => partial
      ? `No ${perm} holder was found, but ${readNote}, so holders may be in the rows not read.`
      : `No active user was found holding ${perm}, yet every org with an active System Administrator has at least one. The audit user most likely cannot see PermissionSetAssignment rows, so this is unknown, not clean.`;
    const unknownRemediation = partial
      ? 'Raise the query row limit (sf config set org-max-query-limit, or SF_ORG_MAX_QUERY_LIMIT) above the assignment count and re-run.'
      : 'Re-run as a user with View Setup and Configuration (or View All Users) so permission set assignments are visible.';
    const modifyRisk = modifyAllCount > 5 ? 'CRITICAL' : modifyAllCount > 3 ? 'HIGH' : 'LOW';
    findings.push({
      id: 'users-modify-all-data',
      category: this.category,
      riskLevel: modifyUnknown ? 'INFO' : modifyRisk,
      ...(modifyUnknown ? { inconclusive: true } : {}),
      title: modifyUnknown
        ? unknownTitle('Modify All Data')
        : `${count(modifyAllCount)} user(s) have Modify All Data permission`,
      detail: modifyUnknown
        ? unknownDetail('Modify All Data')
        : 'Modify All Data grants unrestricted write access across all objects. This is one of the most powerful permissions in Salesforce.',
      remediation: modifyUnknown
        ? unknownRemediation
        : 'Limit Modify All Data to essential system administrators only. Review each user and remove the permission from any non-essential accounts.',
      affectedItems: modifyAllUsers.map((r) => userItem(r as PsaRecord)),
    });

    const viewRisk = viewAllCount > 10 ? 'HIGH' : viewAllCount > 5 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'users-view-all-data',
      category: this.category,
      riskLevel: viewUnknown ? 'INFO' : viewRisk,
      ...(viewUnknown ? { inconclusive: true } : {}),
      title: viewUnknown
        ? unknownTitle('View All Data')
        : `${count(viewAllCount)} user(s) have View All Data permission`,
      detail: viewUnknown
        ? unknownDetail('View All Data')
        : 'View All Data grants unrestricted read access across all objects, bypassing sharing rules and record-level security.',
      remediation: viewUnknown
        ? unknownRemediation
        : 'Limit View All Data to essential users. Consider using permission sets scoped to specific objects instead.',
      affectedItems: viewAllUsers.map((r) => userItem(r as PsaRecord)),
    });

    if (customizeAppCount > 5) {
      findings.push({
        id: 'users-customize-application',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count(customizeAppCount)} user(s) have Customize Application permission`,
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
        title: `${count(authorApexCount)} user(s) have Author Apex permission`,
        detail: 'Author Apex allows users to write and deploy Apex code, which can execute server-side logic with elevated privileges.',
        remediation: 'Author Apex allows code deployment. Limit to developers with a genuine need.',
        affectedItems: authorApexUsers.map((r) => userItem(r as PsaRecord)),
      });
    }

    return {
      findings,
      metrics: {
        totalActiveUsers,
        // An unknown or lower-bound count is left out rather than reported as an exact number;
        // see unknownMetrics.
        ...(modifyUnknown || partial ? {} : { modifyAllDataUsersCount: modifyAllCount }),
        ...(viewUnknown || partial ? {} : { viewAllDataUsersCount: viewAllCount }),
      },
    };
  }
}
