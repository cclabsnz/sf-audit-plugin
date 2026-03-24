import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LoginHistoryRecord {
  UserId: string;
  LoginTime: string;
  SourceIp: string;
  Status: string;
  LoginType: string;
  Application: string;
  Browser: string;
  Platform: string;
}

export class LoginSessionCheck implements SecurityCheck {
  readonly id = 'login-session';
  readonly name = 'Login Session';
  readonly category = 'Session Security';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Query login history for the last 30 days
    const loginRecords = await ctx.soql.queryAll<LoginHistoryRecord>(
      `SELECT UserId, LoginTime, SourceIp, Status, LoginType, Application, Browser, Platform
       FROM LoginHistory
       WHERE LoginTime > LAST_N_DAYS:30
       ORDER BY LoginTime DESC
       LIMIT 2000`
    );

    // Calculate failed login attempts
    const failedLogins = loginRecords.filter((r) => r.Status !== 'Success');
    const failedCount = failedLogins.length;
    const totalLogins = loginRecords.length;

    const failedRiskLevel =
      failedCount > 50 ? 'HIGH' : failedCount > 20 ? 'MEDIUM' : 'LOW';

    findings.push({
      id: 'failed-logins',
      category: this.category,
      riskLevel: failedRiskLevel,
      title: `${failedCount} failed login attempt(s) in the last 30 days`,
      detail: `There were ${failedCount} failed login attempts out of ${totalLogins} total logins in the last 30 days.`,
      remediation:
        'Investigate accounts with repeated failures. Consider IP restrictions or additional MFA policies for high-failure accounts.',
    });

    // Check for API logins from many distinct IPs
    const apiLogins = loginRecords.filter(
      (r) =>
        r.LoginType &&
        (r.LoginType.includes('API') ||
          r.LoginType === 'OAuth 2.0' ||
          r.LoginType === 'SAML')
    );

    if (apiLogins.length > 0) {
      const distinctIps = new Set(apiLogins.map((r) => r.SourceIp));
      const distinctIpCount = distinctIps.size;

      if (distinctIpCount > 10) {
        findings.push({
          id: 'api-logins-many-ips',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `API logins detected from ${distinctIpCount} distinct IP addresses`,
          detail:
            'API access from many different IP addresses may indicate credential sharing or automation abuse.',
          remediation:
            'Review API-connected apps and users. Restrict API access to known IP ranges where possible.',
        });
      }
    }

    return {
      findings,
      metrics: {
        failedLogins30d: failedCount,
      },
    };
  }
}
