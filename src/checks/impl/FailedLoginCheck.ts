import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FailedLoginAgg {
  Username: string;
  // COUNT(Id) is returned as expr0 in SOQL aggregate queries
  expr0: number;
}

interface StatusAgg {
  Status: string;
  expr0: number;
}

interface UserStatusAgg extends StatusAgg {
  UserId: string;
}

// LoginHistory has no IsSuccess field, and Status cannot be filtered (not in WHERE, not in
// HAVING). It can be grouped, so failures are counted by grouping on Status and dropping the
// 'Success' group in code.
const SUCCESS = 'Success';
// An aggregate query returns at most 2,000 groups and cannot be paged.
const MAX_GROUPS = 2000;

// Thresholds for brute-force / credential stuffing detection (7-day window)
const BRUTE_FORCE_PER_USER = 20;    // >20 failures for one user = targeted attack
const BULK_THRESHOLD_PER_USER = 50; // >50 = highly likely automated attack
const ORG_TOTAL_HIGH = 500;         // org-wide failures indicating broad credential stuffing

export class FailedLoginCheck implements SecurityCheck {
  readonly id = 'failed-login-detection';
  readonly name = 'Failed Login Detection';
  readonly category = 'Threat Detection';
  readonly description =
    'Analyses LoginHistory to detect brute-force and credential stuffing patterns from the last 7 days';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/LoginHistory/home`;

    // Query 1: total failed logins in last 7 days
    let totalFailures = 0;
    try {
      const byStatus = await ctx.soql.query<StatusAgg>(
        `SELECT Status, COUNT(Id) FROM LoginHistory WHERE LoginTime > LAST_N_DAYS:7 GROUP BY Status`,
      );
      totalFailures = byStatus.records.filter((r) => r.Status !== SUCCESS).reduce((n, r) => n + r.expr0, 0);
    } catch (err) {
      findings.push({
        id: 'failed-login-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'LoginHistory could not be queried: failed login analysis skipped',
        detail:
          `The LoginHistory query failed: ${err instanceof Error ? err.message : String(err)}. ` +
          'If the org denied access, the audit user may lack "View All Users".',
        remediation:
          'Grant "View All Users" to the audit user. For event-level access, enable Event Monitoring.',
      });
      return { findings };
    }

    if (totalFailures === 0) {
      findings.push({
        id: 'failed-login-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No failed logins in the last 7 days',
        detail: 'No failed login attempts were recorded in the last 7 days.',
        remediation:
          'Continue monitoring LoginHistory. Configure Transaction Security Policies to alert on anomalous login patterns.',
      });
      return { findings };
    }

    // Query 2: per-user aggregation to detect targeted brute force
    let perUserCounts: FailedLoginAgg[] = [];
    let perUserUnavailable = false;
    try {
      const aggResult = await ctx.soql.query<UserStatusAgg>(
        `SELECT UserId, Status, COUNT(Id)
         FROM LoginHistory
         WHERE LoginTime > LAST_N_DAYS:7
         GROUP BY UserId, Status
         ORDER BY COUNT(Id) DESC
         LIMIT ${MAX_GROUPS}`,
      );
      const failuresByUser = new Map<string, number>();
      for (const r of aggResult.records) {
        if (r.Status === SUCCESS) continue;
        failuresByUser.set(r.UserId, (failuresByUser.get(r.UserId) ?? 0) + r.expr0);
      }
      const ranked = [...failuresByUser.entries()].sort((a, b) => b[1] - a[1]).slice(0, 50);
      // LoginHistory has no Username field and no User relationship: resolve names separately.
      const names = new Map<string, string>();
      if (ranked.length > 0) {
        const inClause = ranked.map(([id]) => `'${id}'`).join(',');
        const users = await ctx.soql.queryAll<{ Id: string; Username: string }>(
          `SELECT Id, Username FROM User WHERE Id IN (${inClause})`,
        );
        for (const u of users) names.set(u.Id, u.Username);
      }
      perUserCounts = ranked.map(([id, n]) => ({ Username: names.get(id) ?? id, expr0: n }));
      // Groups are ranked by size across every status, so a full page may have cut off smaller
      // failure groups. Targets found stand; "no target" is then not a conclusion.
      if (aggResult.records.length >= MAX_GROUPS && !perUserCounts.some((r) => r.expr0 >= BRUTE_FORCE_PER_USER)) {
        perUserUnavailable = true;
      }
    } catch {
      // Recorded: without the per-user breakdown, "no brute-force pattern" is not a
      // conclusion this check can reach, only a question it could not answer.
      perUserUnavailable = true;
    }

    const bruteForceTargets = perUserCounts.filter((r) => r.expr0 >= BRUTE_FORCE_PER_USER);
    const heavyTargets = bruteForceTargets.filter((r) => r.expr0 >= BULK_THRESHOLD_PER_USER);

    if (heavyTargets.length > 0) {
      findings.push({
        id: 'failed-login-heavy-brute-force',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${heavyTargets.length} account(s) under heavy brute-force attack (50+ failures in 7 days)`,
        detail:
          `${heavyTargets.length} user account(s) have received 50 or more failed login attempts in the last 7 days. This volume is consistent with automated credential stuffing or targeted brute-force attacks. A successful compromise of any of these accounts gives the attacker full access to that user's Salesforce data and permissions. Automated attacks often use credential lists from third-party data breaches.`,
        remediation:
          'Immediately review these accounts: (1) Reset credentials; (2) Force MFA; (3) Check for concurrent successful logins from unexpected locations; (4) Enable Transaction Security Policies to block logins after N failures; (5) Restrict login access by IP if the user has a known IP range.',
        affectedItems: heavyTargets.map((r) => ({
          label: r.Username,
          url: setupUrl,
          note: `${r.expr0} failed attempts in 7 days: likely automated attack`,
        })),
      });
    }

    if (bruteForceTargets.length > heavyTargets.length) {
      const remaining = bruteForceTargets.filter((r) => r.expr0 < BULK_THRESHOLD_PER_USER);
      findings.push({
        id: 'failed-login-brute-force',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${remaining.length} account(s) with 20+ failed logins in 7 days`,
        detail:
          `${remaining.length} user account(s) have received 20 or more failed login attempts in the last 7 days. This pattern may indicate targeted password-guessing attacks or credential reuse attempts from data breaches. Even a single successful login from an ongoing attack represents a full account compromise.`,
        remediation:
          'Review these accounts for successful logins from unexpected locations. Consider enforcing IP-based login restrictions and enabling MFA if not already in place. Configure Transaction Security Policies to auto-block logins after repeated failures.',
        affectedItems: remaining.map((r) => ({
          label: r.Username,
          url: setupUrl,
          note: `${r.expr0} failed attempts in 7 days`,
        })),
      });
    }

    if (totalFailures >= ORG_TOTAL_HIGH && bruteForceTargets.length === 0) {
      findings.push({
        id: 'failed-login-org-wide',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${totalFailures} failed logins across the org in the last 7 days`,
        detail:
          `The org has recorded ${totalFailures} failed login attempts in 7 days distributed across many accounts. This pattern is consistent with broad credential stuffing: attackers using large lists of username/password combinations from data breaches, targeting the entire org rather than specific accounts. Even a low success rate across many attempts can yield multiple compromised accounts.`,
        remediation:
          'Review Login History for patterns (source IPs, time clustering, usernames). Enable Transaction Security Policies to rate-limit or block logins from suspicious IPs. Consider enabling Salesforce Shield or Event Monitoring for deeper login analytics.',
        affectedItems: [
          {
            label: 'Org-wide login activity',
            url: setupUrl,
            note: `${totalFailures} failures in 7 days: review for patterns`,
          },
        ],
      });
    } else if (totalFailures > 0 && bruteForceTargets.length === 0 && perUserUnavailable) {
      findings.push({
        id: 'failed-login-per-user-unavailable',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `${totalFailures} failed login(s) in 7 days, but the per-account breakdown could not be read`,
        detail:
          `${totalFailures} failed login attempts were recorded org-wide in the last 7 days. The per-username aggregation was not available, so whether any single account is under a brute-force attack could not be determined. The total alone does not distinguish widespread user error from a concentrated attack on one account.`,
        remediation:
          'Grant the audit user access to aggregate LoginHistory queries and re-run, or review Login History grouped by username manually in Setup.',
        affectedItems: [{ label: 'Org-wide login activity', url: setupUrl, note: `${totalFailures} failures in 7 days` }],
      });
    } else if (totalFailures > 0 && bruteForceTargets.length === 0) {
      findings.push({
        id: 'failed-login-low-volume',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${totalFailures} failed login(s) in 7 days: no brute-force patterns detected`,
        detail: `${totalFailures} failed login attempts recorded in the last 7 days, but no single account exceeded the brute-force threshold (${BRUTE_FORCE_PER_USER} failures). This volume appears consistent with normal user error.`,
        remediation:
          'Continue monitoring. Configure Transaction Security Policies to alert on anomalous login activity as volumes change.',
      });
    }

    return { findings };
  }
}
