import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PortalUserRecord {
  Id: string;
  Username: string;
  UserType: string;
  Profile: { Name: string };
}

// Experience Cloud / portal user types that represent external human users
const EXTERNAL_USER_TYPES = ['CsnOnly', 'CustomerSuccess', 'PowerPartner', 'PowerCustomerSuccess', 'SelfService'];

export class MfaEnforcementCheck implements SecurityCheck {
  readonly id = 'mfa-enforcement';
  readonly name = 'MFA for External Users';
  readonly category = 'Authentication';
  readonly description = 'SBS-AUTH-004: checks that external/portal users with data access have MFA enforced';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const userTypeList = EXTERNAL_USER_TYPES.map((t) => `'${t}'`).join(', ');

    // Query 1: all active external/portal users
    const allPortalResult = await ctx.soql.queryAll<PortalUserRecord>(
      `SELECT Id, Username, UserType, Profile.Name
       FROM User
       WHERE IsActive = true
         AND UserType IN (${userTypeList})
       ORDER BY UserType, Username
       LIMIT 500`
    );
    const allPortalUsers = allPortalResult;

    if (allPortalUsers.length === 0) {
      findings.push({
        id: 'mfa-no-portal-users',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active external/portal users found: SBS-AUTH-004 not applicable',
        detail: 'SBS-AUTH-004 applies to external users with substantial access to sensitive data. No active portal user types were found in this org.',
        remediation: 'If Experience Cloud sites are added in future, ensure SBS-AUTH-004 MFA requirements are met for external users.',
      });
      return { findings };
    }

    // Query 2: portal users who have MFA explicitly enforced via permission
    let mfaEnforcedIds = new Set<string>();
    try {
      const mfaResult = await ctx.soql.query<{ AssigneeId: string }>(
        `SELECT AssigneeId
         FROM PermissionSetAssignment
         WHERE PermissionSet.PermissionsMultiFactorForUiLogins = true
           AND Assignee.IsActive = true
           AND Assignee.UserType IN (${userTypeList})`
      );
      mfaEnforcedIds = new Set(mfaResult.records.map((r) => r.AssigneeId));
    } catch {
      // PermissionsMultiFactorForUiLogins may not exist in all editions — treat as none enforced
    }

    const withoutMfa = allPortalUsers.filter((u) => !mfaEnforcedIds.has(u.Id));
    const withMfa = allPortalUsers.filter((u) => mfaEnforcedIds.has(u.Id));

    if (withoutMfa.length === 0) {
      findings.push({
        id: 'mfa-portal-users-enforced',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${allPortalUsers.length} external/portal user(s) have MFA enforced`,
        detail: 'SBS-AUTH-004 requires MFA for external users with substantial access. All active portal users have the "Multi-Factor Authentication for User Interface Logins" permission assigned.',
        remediation: 'Continue monitoring as new portal users are added.',
      });
      return { findings };
    }

    const riskLevel = withoutMfa.length > 10 ? 'HIGH' : 'MEDIUM';

    findings.push({
      id: 'mfa-portal-users-without-enforcement',
      category: this.category,
      riskLevel,
      title: `${withoutMfa.length} of ${allPortalUsers.length} external/portal user(s) do not have MFA enforced: SBS-AUTH-004`,
      detail:
        `SBS-AUTH-004 requires all external human users with substantial access to sensitive data to enforce MFA including at least one strong authentication factor. ${withoutMfa.length} active portal user(s) lack the "Multi-Factor Authentication for User Interface Logins" permission. ${withMfa.length > 0 ? `${withMfa.length} user(s) already have MFA enforced.` : ''}`,
      remediation:
        'Assign the "Multi-Factor Authentication for User Interface Logins" permission to all Experience Cloud users with access to sensitive data. Create a permission set for this purpose and assign it to all in-scope portal profiles.',
      affectedItems: withoutMfa.slice(0, 50).map((u) => ({
        label: u.Username,
        url: `${baseUrl}/${u.Id}`,
        note: `UserType: ${u.UserType} | Profile: ${u.Profile.Name} | assign MFA permission set`,
      })),
    });

    return { findings };
  }
}
