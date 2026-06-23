import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FailedLoginAgg {
  Username: string;
  // COUNT(Id) is returned as expr0 in SOQL aggregate queries
  expr0: number;
}

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
      const countResult = await ctx.soql.query<Record<string, never>>(
        `SELECT COUNT() FROM LoginHistory WHERE IsSuccess = false AND LoginTime > LAST_N_DAYS:7`,
      );
      totalFailures = countResult.totalSize;
    } catch {
      findings.push({
        id: 'failed-login-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'LoginHistory could not be queried: failed login analysis skipped',
        detail:
          'The LoginHistory SOQL query was not accessible. This may indicate the audit user lacks "View All Users" or event monitoring access.',
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
    try {
      const aggResult = await ctx.soql.query<FailedLoginAgg>(
        `SELECT Username, COUNT(Id)
         FROM LoginHistory
         WHERE IsSuccess = false AND LoginTime > LAST_N_DAYS:7
         GROUP BY Username
         ORDER BY COUNT(Id) DESC
         LIMIT 50`,
      );
      perUserCounts = aggResult.records;
    } catch {
      // Per-user breakdown unavailable — still emit org-level finding
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
