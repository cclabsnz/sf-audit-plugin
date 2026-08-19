import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface UserRecord {
  Id: string;
  Username: string;
  Profile: { Name: string } | null;
  LastLoginDate: string | null;
}

interface PsaRecord {
  AssigneeId: string;
}

export class InternalUserMfaCheck implements SecurityCheck {
  readonly id = 'internal-user-mfa';
  readonly name = 'Internal User MFA Enforcement';
  readonly category = 'Authentication';
  readonly description = 'Checks MFA enforcement for all active internal standard users';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // queryAll to avoid LIMIT 500 truncation — PSA query below fetches all records,
    // so a truncated user list would produce false-pass results for the missing users.
    const users = await ctx.soql.queryAll<UserRecord>(
      `SELECT Id, Username, Profile.Name, LastLoginDate
       FROM User
       WHERE IsActive = true
         AND UserType = 'Standard'
         AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)
       ORDER BY Username`
    );

    if (users.length === 0) {
      findings.push({
        id: 'internal-user-mfa-all-enforced',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active internal standard users found',
        detail:
          'No active, unfrozen standard users were found in this org. MFA enforcement verification is not applicable.',
        remediation: 'No action required.',
      });
      return { findings };
    }

    let mfaUserIds = new Set<string>();
    try {
      const psaResult = await ctx.soql.query<PsaRecord>(
        `SELECT AssigneeId
         FROM PermissionSetAssignment
         WHERE PermissionSet.PermissionsMultiFactorForUiLogins = true
           AND Assignee.IsActive = true
           AND Assignee.UserType = 'Standard'`
      );
      mfaUserIds = new Set(psaResult.records.map((r) => r.AssigneeId));
    } catch {
      findings.push({
        id: 'internal-user-mfa-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'MFA permission set assignments could not be queried',
        detail:
          'The PermissionSetAssignment query for PermissionsMultiFactorForUiLogins was not accessible. This may indicate insufficient permissions to query permission set assignments.',
        remediation:
          'Grant "View All Users" or "Manage Users" permission to the audit user. Review MFA enforcement manually in Setup → Users → Permission Sets.',
      });
      return { findings };
    }

    const usersWithoutMfa = users.filter((u) => !mfaUserIds.has(u.Id));

    if (usersWithoutMfa.length === 0) {
      findings.push({
        id: 'internal-user-mfa-all-enforced',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${users.length} active internal user(s) have MFA explicitly enforced via permission`,
        detail:
          'All active, unfrozen standard users have the PermissionsMultiFactorForUiLogins permission assigned. Salesforce auto-enforced MFA at the system level in Spring 2023; this explicit permission provides belt-and-suspenders assurance that MFA is enforced even if system-level enforcement has edge cases.',
        remediation:
          'Continue to ensure all new users are assigned MFA enforcement via their profile or a permission set.',
      });
      return { findings };
    }

    const riskLevel = usersWithoutMfa.length > 20 ? 'HIGH' : 'MEDIUM';

    findings.push({
      id: 'internal-user-mfa-gaps',
      category: this.category,
      riskLevel,
      title: `${usersWithoutMfa.length} of ${users.length} active internal user(s) lack explicit MFA enforcement permission`,
      detail:
        `${usersWithoutMfa.length} active standard users do not have the PermissionsMultiFactorForUiLogins permission assigned. Salesforce auto-enforced MFA at the system level in Spring 2023, but the explicit permission provides belt-and-suspenders assurance. Users without it rely solely on system-level enforcement, which can have edge cases in API-heavy or SSO-integrated environments. Users without the explicit permission should be reviewed to confirm they are subject to effective MFA controls.`,
      remediation:
        'Assign the "Multi-Factor Authentication for User Interface Logins" permission to all internal standard users via their profile or a permission set. This ensures MFA is explicitly enforced regardless of system-level settings. Prioritise users with privileged access or access to sensitive data.',
      affectedItems: usersWithoutMfa.slice(0, 50).map((u) => ({
        label: u.Username,
        url: `${baseUrl}/${u.Id}`,
        note: `profile: ${u.Profile?.Name ?? 'unknown'} | last login: ${u.LastLoginDate ? new Date(u.LastLoginDate).toISOString().split('T')[0] : 'never'}`,
      })),
    });

    return { findings };
  }
}
