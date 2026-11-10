import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LoginHistoryRecord {
  Id: string;
  UserId: string;
  LoginType: string;
  LoginSubType?: string;
  LoginTime: string;
}

interface UserRecord {
  Id: string;
  Username: string;
}

export class SsoEnforcementCheck implements SecurityCheck {
  readonly id = 'sso-enforcement';
  readonly name = 'SSO Enforcement';
  readonly category = 'Authentication';
  readonly description = 'SBS-AUTH-001/002: detects username-password logins indicating SSO is not org-wide enforced';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    try {
      // Single query: recent credential logins over the past 30 days.
      // Logins with Salesforce credentials are direct evidence that SBS-AUTH-001 (org-wide SSO
      // enforcement) is not fully applied. LoginSubType records them, through the UI or the OAuth
      // username-password flow; LoginType has no 'Username-Password' value, so a filter on it
      // matched nothing and every org passed.
      const result = await ctx.soql.queryAll<LoginHistoryRecord>(
        // LoginHistory carries no Username field and no User relationship; names are resolved below.
        `SELECT Id, UserId, LoginType, LoginSubType, LoginTime
         FROM LoginHistory
         WHERE LoginTime > LAST_N_DAYS:30
           AND LoginSubType IN ('UI Username-Password', 'OAuth Username-Password')
         ORDER BY LoginTime DESC
         LIMIT 300`
      );

      const records = result;

      if (records.length === 0) {
        findings.push({
          id: 'sso-no-password-logins',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No username-password logins detected in the last 30 days',
          detail:
            'SBS-AUTH-001 requires production orgs to disable Salesforce credential logins. No username-password logins were found in LoginHistory for the past 30 days, which is consistent with SSO being enforced.',
          remediation:
            'Verify in Setup → Single Sign-On Settings that "Prevent Login with Salesforce Credentials" is enabled to enforce SBS-AUTH-001 at the org level.',
        });
        return { findings };
      }

      // Deduplicate by user to find unique users bypassing SSO
      const byUser = new Map<string, { username: string; count: number; latest: string }>();
      for (const r of records) {
        const existing = byUser.get(r.UserId);
        if (existing) {
          existing.count++;
        } else {
          byUser.set(r.UserId, { username: r.UserId, count: 1, latest: r.LoginTime });
        }
      }

      // At most 300 logins, so at most 300 distinct users: one bounded lookup.
      const inClause = [...byUser.keys()].map((id) => `'${id}'`).join(',');
      const users = await ctx.soql.queryAll<UserRecord>(`SELECT Id, Username FROM User WHERE Id IN (${inClause})`);
      for (const u of users) {
        const entry = byUser.get(u.Id);
        if (entry) entry.username = u.Username;
      }

      const uniqueUsers = [...byUser.entries()];

      findings.push({
        id: 'sso-password-logins-detected',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${uniqueUsers.length} user(s) logged in with username-password credentials in the last 30 days: SBS-AUTH-001/002`,
        detail:
          `SBS-AUTH-001 requires production orgs to enable the org-level setting that disables Salesforce credential logins for all users. SBS-AUTH-002 requires that any users permitted to bypass SSO be explicitly authorised and documented. Found ${records.length} password-based login(s) across ${uniqueUsers.length} unique user(s) in the past 30 days, indicating SSO is either not enforced org-wide or users have undocumented SSO bypass.`,
        remediation:
          'Enable "Prevent Login with Salesforce Credentials" in Setup → Single Sign-On Settings (SBS-AUTH-001). For any users who legitimately need credential login (break-glass accounts), document their authorisation in the system of record (SBS-AUTH-002) and restrict their profile IP ranges.',
        affectedItems: uniqueUsers.map(([userId, info]) => ({
          label: info.username,
          url: `${baseUrl}/${userId}`,
          note: `${info.count} credential login(s), last: ${new Date(info.latest).toISOString().split('T')[0]}`,
        })),
      });

      // Advisory: flag users who appear to be SSO-exempt service accounts
      const highFrequency = uniqueUsers.filter(([, v]) => v.count > 10);
      if (highFrequency.length > 0) {
        findings.push({
          id: 'sso-frequent-bypass-users',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${highFrequency.length} user(s) logged in with credentials >10 times, likely undocumented SSO exemptions (SBS-AUTH-002)`,
          detail:
            'SBS-AUTH-002 requires all users permitted to bypass SSO to be explicitly documented. High-frequency credential logins suggest these are regular exemptions rather than emergency break-glass access.',
          remediation:
            'Document each user in the system of record with a justified reason for SSO bypass. Consider converting service accounts to Connected App OAuth flows instead.',
          affectedItems: highFrequency.map(([userId, info]) => ({
            label: info.username,
            url: `${baseUrl}/${userId}`,
            note: `${info.count} credential logins in 30 days, document or remove exemption`,
          })),
        });
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'sso-enforcement-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'SSO enforcement status could not be determined: LoginHistory could not be read',
        detail:
          `SBS-AUTH-001/002 require SSO enforcement configuration to be verified. LoginHistory could not be read: ${reason}`,
        remediation:
          'Manually verify in Setup → Single Sign-On Settings that "Prevent Login with Salesforce Credentials" is enabled.',
      });
    }

    return { findings };
  }
}
