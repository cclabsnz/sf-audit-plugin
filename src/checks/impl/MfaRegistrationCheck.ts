import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface MethodsRecord {
  UserId: string;
  User: {
    Username: string;
    Profile: { Name: string } | null;
  } | null;
  HasTotp?: boolean;
  HasSalesforceAuthenticator?: boolean;
  HasU2F?: boolean;
  HasSecurityKey?: boolean;
  HasBuiltInAuthenticator?: boolean;
  HasUserVerifiedMobileNumber?: boolean;
  HasVerifiedMobileNumber?: boolean;
  HasUserVerifiedEmailAddress?: boolean;
  HasTempCode?: boolean;
}

/**
 * TwoFactorMethodsInfo flags, mapped to the method names MfaMethodStrengthCheck grades. TwoFactorInfo
 * is not used: its Type picklist holds only 'TOTP', so it never shows Salesforce Authenticator,
 * security keys or built-in authenticators.
 */
const METHOD_FLAGS: Array<[keyof MethodsRecord, string]> = [
  ['HasSecurityKey', 'FIDO2'],
  ['HasU2F', 'U2F'],
  ['HasBuiltInAuthenticator', 'BUILT_IN_AUTHENTICATOR'],
  ['HasSalesforceAuthenticator', 'SALESFORCE_AUTHENTICATOR'],
  ['HasTotp', 'TOTP'],
  ['HasUserVerifiedMobileNumber', 'SMS_OTP'],
  ['HasVerifiedMobileNumber', 'SMS_OTP'],
  ['HasUserVerifiedEmailAddress', 'EMAIL'],
  ['HasTempCode', 'VERIFICATIONCODE'],
];
// Methods that satisfy Salesforce's MFA requirement. A verified phone or email address, or a
// temporary code, is a sign-in fallback, not an MFA registration.
const QUALIFYING = new Set(['FIDO2', 'U2F', 'BUILT_IN_AUTHENTICATOR', 'SALESFORCE_AUTHENTICATOR', 'TOTP']);

export class MfaRegistrationCheck implements SecurityCheck {
  readonly id = 'mfa-registration';
  readonly name = 'MFA Method Registration';
  readonly category = 'Authentication';
  readonly description = 'Identifies active standard users who have not registered an MFA method (authenticator app, Salesforce Authenticator, security key or built-in authenticator) in TwoFactorMethodsInfo';

  readonly populatesCache = ['mfaRegistrations'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SetupOneIdEntityManagement/home`;

    const frozenFilter = `Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`;
    // COUNT(Id) with no alias puts the result in records[0].expr0 (an explicit expr0 alias is
    // reserved and rejected); COUNT() without a field puts it in
    // totalSize which is not exposed on the typed return value.
    const countResult = await ctx.soql.query<{ expr0: number }>(
      `SELECT COUNT(Id) FROM User
       WHERE IsActive = true
         AND UserType = 'Standard'
         AND ${frozenFilter}`
    );
    const totalActiveUsers = countResult.records[0]?.expr0 ?? 0;

    // Same population as the count: active, unfrozen standard users. Frozen users are dropped from
    // the registrations below client-side; a semi-join on TwoFactorMethodsInfo has not been tested against a
    // live org. Like the count, this reads UserLogin outside the TwoFactorMethodsInfo error handling.
    const frozen = new Set(
      (await ctx.soql.queryAll<{ UserId: string }>(`SELECT UserId FROM UserLogin WHERE IsFrozen = true`))
        .map((r) => r.UserId),
    );

    let methodRecords: MethodsRecord[] = [];
    try {
      // queryAll pages through every row, so a large org is not cut off at a fixed limit and its
      // remaining users counted as unregistered.
      methodRecords = (await ctx.soql.queryAll<MethodsRecord>(
        `SELECT UserId, User.Username, User.Profile.Name, ${METHOD_FLAGS.map(([f]) => f).join(', ')}
         FROM TwoFactorMethodsInfo
         WHERE User.IsActive = true
           AND User.UserType = 'Standard'
         ORDER BY UserId`
      )).filter((r) => !frozen.has(r.UserId));
    } catch {
      // Leave the cache unset: an empty list would read downstream as "nobody registered MFA".
      findings.push({
        id: 'mfa-registration-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'TwoFactorMethodsInfo could not be queried: MFA registration status cannot be verified',
        detail:
          'The TwoFactorMethodsInfo object was not accessible. The audit user most likely lacks the "Manage MFA in API" permission (PermissionsManageTwoFactor), which hides the object.',
        remediation:
          'Grant the audit user "Manage MFA in API" through a permission set, or review MFA registration manually in Setup → Identity → Identity Verification. Salesforce grants it only with user-management permissions (Manage Users, Manage Internal Users, Manage Sharing, Manage Roles, Reset Passwords and others; PERMISSIONS.md lists them), so it suits an audit user who is already an administrator.',
        affectedItems: [{ label: 'Identity Verification Setup', url: setupUrl }],
      });
      return { findings };
    }

    // Only users with a qualifying method are registered, and only they go to the cache: a user
    // with just a verified phone, email or temporary code has no MFA method, and is reported here
    // as unregistered, not graded by the strength check as "weak MFA" (which would rate an admin
    // who verified an email worse than one who did nothing). Their fallbacks still appear in the
    // cached methods of registered users.
    const userMethodMap = new Map<string, { username: string; profileName: string; methods: string[] }>();
    for (const r of methodRecords) {
      const methods = [...new Set(METHOD_FLAGS.filter(([f]) => r[f] === true).map(([, m]) => m))];
      if (methods.length === 0) continue;
      const existing = userMethodMap.get(r.UserId);
      if (existing) {
        existing.methods = [...new Set([...existing.methods, ...methods])];
      } else {
        userMethodMap.set(r.UserId, {
          username: r.User?.Username ?? r.UserId,
          profileName: r.User?.Profile?.Name ?? 'Unknown',
          methods,
        });
      }
    }

    ctx.cache.mfaRegistrations = [...userMethodMap.entries()].filter(([, data]) => data.methods.some((m) => QUALIFYING.has(m))).map(([userId, data]) => ({
      userId,
      username: data.username,
      profileName: data.profileName,
      methods: data.methods,
    }));

    const registeredCount = [...userMethodMap.values()].filter((u) => u.methods.some((m) => QUALIFYING.has(m))).length;
    const fallbackOnly = userMethodMap.size - registeredCount;
    const unregisteredCount = Math.max(0, totalActiveUsers - registeredCount);

    // The audit user is itself an active standard user, so a count of 0 means the count could not
    // see users, not that there are none: inconclusive, never a pass.
    if (totalActiveUsers === 0) {
      findings.push({
        id: 'mfa-registration-no-users-visible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'No active standard users were visible: MFA registration cannot be checked',
        detail: 'The count of active, unfrozen standard users returned 0, although the audit user is one. The audit user may not be able to read User records.',
        remediation: 'Grant the audit user "View Setup and Configuration" and "Manage Users" read access, then re-run, or review MFA registration manually in Setup → Identity → Identity Verification.',
        affectedItems: [{ label: 'Identity Verification Setup', url: setupUrl }],
      });
      return { findings };
    }

    if (unregisteredCount === 0) {
      findings.push({
        id: 'mfa-registration-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${totalActiveUsers} active standard user(s) have registered at least one MFA method`,
        detail:
          `All ${totalActiveUsers} active, unfrozen standard users have at least one MFA method registered (authenticator app, Salesforce Authenticator, security key or built-in authenticator). Users who have not registered a method cannot complete MFA challenges and may be locked out of the org if MFA is enforced.`,
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
        `${unregisteredCount} active standard users have no MFA method registered: no authenticator app, Salesforce Authenticator, security key or built-in authenticator. These users cannot complete MFA challenges and may be locked out or have a degraded authentication experience when MFA is enforced. ${registeredCount} user(s) have registered at least one method.${fallbackOnly > 0 ? ` ${fallbackOnly} of the unregistered user(s) have only a verified phone number, email address or temporary code, which are sign-in fallbacks, not MFA methods.` : ''} Unregistered users should complete MFA setup immediately.`,
      remediation:
        'Identify unregistered users in Setup → Identity → Identity Verification → User Management. Send MFA registration prompts or require registration on next login. Consider using Salesforce automation or the MFA rollout tools to enforce registration deadlines.',
      affectedItems: [
        {
          label: `${unregisteredCount} unregistered user(s)`,
          url: setupUrl,
          note: `${totalActiveUsers} total active users (${registeredCount} registered, ${unregisteredCount} unregistered)`,
        },
      ],
    });

    return { findings };
  }
}
