import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface TwoFactorRecord {
  UserId: string;
  User: {
    Username: string;
    Profile: { Name: string } | null;
  };
  Type: string;
}

export class MfaRegistrationCheck implements SecurityCheck {
  readonly id = 'mfa-registration';
  readonly name = 'MFA Method Registration';
  readonly category = 'Authentication';
  readonly description = 'Identifies active standard users who have not registered any MFA method in TwoFactorInfo';

  readonly populatesCache = ['mfaRegistrations'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SetupOneIdEntityManagement/home`;

    const frozenFilter = `Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`;
    // COUNT(Id) expr0 puts the result in records[0].expr0; COUNT() without a field puts it in
    // totalSize which is not exposed on the typed return value.
    const countResult = await ctx.soql.query<{ expr0: number }>(
      `SELECT COUNT(Id) expr0 FROM User
       WHERE IsActive = true
         AND UserType = 'Standard'
         AND ${frozenFilter}`
    );
    const totalActiveUsers = countResult.records[0]?.expr0 ?? 0;

    let twoFactorRecords: TwoFactorRecord[] = [];
    try {
      twoFactorRecords = await ctx.soql.queryAll<TwoFactorRecord>(
        `SELECT UserId, User.Username, User.Profile.Name, Type
         FROM TwoFactorInfo
         WHERE User.IsActive = true
           AND User.UserType = 'Standard'
         ORDER BY UserId
         LIMIT 2000`
      );
    } catch {
      ctx.cache.mfaRegistrations = [];
      findings.push({
        id: 'mfa-registration-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'TwoFactorInfo could not be queried — MFA registration status cannot be verified',
        detail:
          'The TwoFactorInfo object was not accessible. This may indicate the audit user lacks the "Manage Multi-Factor Authentication in API" permission or the org edition does not support this query.',
        remediation:
          'Grant "Manage Multi-Factor Authentication in API" permission to the audit user. Review MFA registration status manually in Setup → Identity → Identity Verification.',
        affectedItems: [{ label: 'Identity Verification Setup', url: setupUrl }],
      });
      return { findings };
    }

    const userMethodMap = new Map<string, { username: string; profileName: string; methods: string[] }>();
    for (const r of twoFactorRecords) {
      const existing = userMethodMap.get(r.UserId);
      if (existing) {
        existing.methods.push(r.Type);
      } else {
        userMethodMap.set(r.UserId, {
          username: r.User.Username,
          profileName: r.User.Profile?.Name ?? 'Unknown',
          methods: [r.Type],
        });
      }
    }

    ctx.cache.mfaRegistrations = [...userMethodMap.entries()].map(([userId, data]) => ({
      userId,
      username: data.username,
      profileName: data.profileName,
      methods: data.methods,
    }));

    const registeredCount = userMethodMap.size;
    const unregisteredCount = Math.max(0, totalActiveUsers - registeredCount);

    if (unregisteredCount === 0) {
      findings.push({
        id: 'mfa-registration-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${totalActiveUsers} active standard user(s) have registered at least one MFA method`,
        detail:
          `All ${totalActiveUsers} active, unfrozen standard users have at least one MFA method registered in TwoFactorInfo. Users who have not registered a method cannot complete MFA challenges and may be locked out of the org if MFA is enforced.`,
        remediation:
          'Continue monitoring MFA registration as new users are onboarded. Ensure new user onboarding includes an MFA registration step before their first login.',
      });
      return { findings };
    }

    const riskLevel = unregisteredCount > 20 ? 'HIGH' : 'MEDIUM';

    findings.push({
      id: 'mfa-registration-gap',
      category: this.category,
      riskLevel,
      title: `${unregisteredCount} of ${totalActiveUsers} active user(s) have not registered any MFA method`,
      detail:
        `${unregisteredCount} active standard users have no registered MFA methods in TwoFactorInfo. These users cannot complete MFA challenges and may be locked out or have a degraded authentication experience when MFA is enforced. ${registeredCount} user(s) have registered at least one method. Unregistered users should complete MFA setup immediately.`,
      remediation:
        'Identify unregistered users in Setup → Identity → Identity Verification → User Management. Send MFA registration prompts or require registration on next login. Consider using Salesforce automation or the MFA rollout tools to enforce registration deadlines.',
      affectedItems: [
        {
          label: `${unregisteredCount} unregistered user(s)`,
          url: setupUrl,
          note: `${totalActiveUsers} total active users — ${registeredCount} registered — ${unregisteredCount} unregistered`,
        },
      ],
    });

    return { findings };
  }
}
