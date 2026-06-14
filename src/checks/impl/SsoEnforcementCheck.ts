import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LoginHistoryRecord {
  Id: string;
  UserId: string;
  Username: string;
  LoginType: string;
  LoginTime: string;
}

export class SsoEnforcementCheck implements SecurityCheck {
  readonly id = 'sso-enforcement';
  readonly name = 'SSO Enforcement';
  readonly category = 'Authentication';
  readonly description = 'SBS-AUTH-001/002: detects username-password logins indicating SSO is not org-wide enforced';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SingleSignOn/home`;

    try {
      // Single query: recent credential logins over the past 30 days.
      // Presence of 'Username-Password' logins is direct evidence that SBS-AUTH-001
      // (org-wide SSO enforcement) is not fully applied.
      const result = await ctx.soql.queryAll<LoginHistoryRecord>(
        `SELECT Id, UserId, Username, LoginType, LoginTime
         FROM LoginHistory
         WHERE LoginTime > LAST_N_DAYS:30
           AND LoginType = 'Username-Password'
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
          byUser.set(r.UserId, { username: r.Username, count: 1, latest: r.LoginTime });
        }
      }

      const uniqueUsers = [...byUser.entries()];

      findings.push({
        id: 'sso-password-logins-detected',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${uniqueUsers.length} user(s) logged in with username-password credentials in the last 30 days — SBS-AUTH-001/002`,
        detail:
          `SBS-AUTH-001 requires production orgs to enable the org-level setting that disables Salesforce credential logins for all users. SBS-AUTH-002 requires that any users permitted to bypass SSO be explicitly authorised and documented. Found ${records.length} password-based login(s) across ${uniqueUsers.length} unique user(s) in the past 30 days, indicating SSO is either not enforced org-wide or users have undocumented SSO bypass.`,
        remediation:
          'Enable "Prevent Login with Salesforce Credentials" in Setup → Single Sign-On Settings (SBS-AUTH-001). For any users who legitimately need credential login (break-glass accounts), document their authorisation in the system of record (SBS-AUTH-002) and restrict their profile IP ranges.',
        affectedItems: uniqueUsers.map(([userId, info]) => ({
          label: info.username,
          url: `${baseUrl}/${userId}`,
          note: `${info.count} credential login(s) — last: ${new Date(info.latest).toISOString().split('T')[0]}`,
        })),
      });

      // Advisory: flag users who appear to be SSO-exempt service accounts
      const highFrequency = uniqueUsers.filter(([, v]) => v.count > 10);
      if (highFrequency.length > 0) {
        findings.push({
          id: 'sso-frequent-bypass-users',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${highFrequency.length} user(s) logged in with credentials >10 times — likely undocumented SSO exemptions (SBS-AUTH-002)`,
          detail:
            'SBS-AUTH-002 requires all users permitted to bypass SSO to be explicitly documented. High-frequency credential logins suggest these are regular exemptions rather than emergency break-glass access.',
          remediation:
            'Document each user in the system of record with a justified reason for SSO bypass. Consider converting service accounts to Connected App OAuth flows instead.',
          affectedItems: highFrequency.map(([userId, info]) => ({
            label: info.username,
            url: `${baseUrl}/${userId}`,
            note: `${info.count} credential logins in 30 days — document or remove exemption`,
          })),
        });
      }
    } catch {
      findings.push({
        id: 'sso-enforcement-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'SSO enforcement status could not be determined — LoginHistory not accessible',
        detail:
          'SBS-AUTH-001/002 require SSO enforcement configuration to be verified. LoginHistory was not accessible with current permissions.',
        remediation:
          'Manually verify in Setup → Single Sign-On Settings that "Prevent Login with Salesforce Credentials" is enabled.',
      });
    }

    return { findings };
  }
}
