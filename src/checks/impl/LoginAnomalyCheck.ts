import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LoginRec {
  UserId: string;
  SourceIp: string | null;
  LoginTime: string;
}

// A single account authenticating successfully from this many distinct source IPs
// in the window is a proxy for credential sharing or account compromise (a real
// person logs in from a small, stable set of networks).
const DISTINCT_IP_THRESHOLD = 8;
const MAX_ROWS = 20000;

/**
 * Complements `failed-login-detection` (which only sees failures) by looking at
 * SUCCESSFUL logins for a compromise signature: one user authenticating from an
 * unusually large number of distinct source IPs in a short window — the footprint
 * of credential sharing, a leaked token replayed from many egress nodes, or an
 * account being driven from attacker infrastructure.
 */
export class LoginAnomalyCheck implements SecurityCheck {
  readonly id = 'login-anomaly';
  readonly name = 'Anomalous Successful Logins';
  readonly category = 'Threat Detection';
  readonly description =
    'Flags user accounts with successful logins from an unusually high number of distinct source IPs (credential-sharing / account-compromise signature)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/OrgLoginHistory/home`;

    let rows: LoginRec[];
    try {
      rows = await ctx.soql.queryAll<LoginRec>(
        `SELECT UserId, SourceIp, LoginTime FROM LoginHistory
         WHERE Status = 'Success' AND LoginTime = LAST_N_DAYS:7
         ORDER BY LoginTime DESC LIMIT ${MAX_ROWS}`,
      );
    } catch {
      findings.push({
        id: 'login-anomaly-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'LoginHistory could not be queried — anomalous-login analysis skipped',
        detail: 'LoginHistory was not accessible. This may indicate the audit user lacks "View All Users"/"Manage Users" or the org restricts login history.',
        remediation: 'Grant the audit user access to LoginHistory and re-run.',
      });
      return { findings };
    }

    if (rows.length === 0) {
      findings.push({
        id: 'login-anomaly-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No successful logins in the last 7 days',
        detail: 'LoginHistory returned no successful logins in the window, so no login-distribution anomaly could be computed.',
        remediation: 'Re-run after normal activity; forward LoginHistory to a SIEM for continuous anomaly detection.',
      });
      return { findings };
    }

    const ipsByUser = new Map<string, Set<string>>();
    for (const r of rows) {
      if (!r.SourceIp) continue;
      const set = ipsByUser.get(r.UserId) ?? new Set<string>();
      set.add(r.SourceIp);
      ipsByUser.set(r.UserId, set);
    }

    const anomalous = [...ipsByUser.entries()].filter(([, ips]) => ips.size >= DISTINCT_IP_THRESHOLD);
    if (rows.length >= MAX_ROWS) {
      findings.push({
        id: 'login-anomaly-truncated',
        category: this.category,
        riskLevel: 'INFO',
        title: `Login history truncated at ${MAX_ROWS} rows — analysis is partial`,
        detail: `The last-7-day successful-login volume exceeded ${MAX_ROWS} rows, so this analysis covers only the most recent window. Some per-user IP spread may be undercounted.`,
        remediation: 'Forward LoginHistory to a SIEM for complete, continuous analysis rather than point-in-time sampling.',
      });
    }

    if (anomalous.length > 0) {
      findings.push({
        id: 'login-anomaly-multi-ip',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${anomalous.length} account(s) logged in from ${DISTINCT_IP_THRESHOLD}+ distinct source IPs in 7 days`,
        detail:
          'These accounts authenticated successfully from an unusually large number of distinct source IPs in a week. That pattern is consistent with credential sharing, a leaked session/token being replayed from many egress nodes, or an account driven from distributed attacker infrastructure.',
        remediation:
          'Investigate these accounts: confirm the logins are legitimate, reset credentials and revoke sessions if not, and enforce MFA + login IP ranges. Consider a Transaction Security Policy that alerts on logins from new geographies/IPs.',
        affectedItems: anomalous
          .sort((a, b) => b[1].size - a[1].size)
          .slice(0, 30)
          .map(([userId, ips]) => ({ label: `${userId} — ${ips.size} distinct IPs`, url: setupUrl })),
      });
    } else {
      findings.push({
        id: 'login-anomaly-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No accounts with an anomalous login-IP spread',
        detail: `Across ${rows.length} successful login(s) in 7 days, no account authenticated from ${DISTINCT_IP_THRESHOLD}+ distinct source IPs.`,
        remediation: 'Continue forwarding LoginHistory to a SIEM for continuous anomaly detection.',
      });
    }

    return { findings };
  }
}
