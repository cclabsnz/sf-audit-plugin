import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ConnectedAppSessionRecord {
  Id: string;
  Name: string;
  SessionTimeout: number | null;
  OptionsAllowAdminApprovedUsersOnly: boolean;
}

// Session timeouts are in seconds in SOQL for ConnectedApplication.
// 8 hours = 28800s; 12 hours = 43200s.
const LONG_TIMEOUT_SECONDS = 8 * 3600;

// Patterns that suggest an app has elevated / admin capabilities
const ADMIN_APP_PATTERNS = [/admin/i, /manage/i, /setup/i, /deploy/i, /devops/i, /audit/i, /monitor/i];

export class HighAssuranceSessionCheck implements SecurityCheck {
  readonly id = 'high-assurance-session';
  readonly name = 'High Assurance Session Requirements';
  readonly category = 'Authentication';
  readonly description = 'Checks whether connected apps with admin-like capabilities require short session timeouts or high-assurance MFA sessions';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ConnectedApplication/home`;

    let apps: ConnectedAppSessionRecord[];
    try {
      const result = await ctx.soql.query<ConnectedAppSessionRecord>(
        `SELECT Id, Name, SessionTimeout, OptionsAllowAdminApprovedUsersOnly
         FROM ConnectedApplication
         ORDER BY Name
         LIMIT 200`
      );
      apps = result.records;
    } catch {
      findings.push({
        id: 'high-assurance-session-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Connected app session settings could not be read',
        detail: 'ConnectedApplication session fields were not accessible. High assurance session configuration cannot be verified.',
        remediation: 'Manually review connected apps in Setup → Connected Apps → Manage Connected Apps and verify session timeout policies.',
      });
      return { findings };
    }

    if (apps.length === 0) {
      findings.push({
        id: 'high-assurance-session-no-apps',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No connected apps found: session policy check not applicable',
        detail: 'No connected apps are configured in this org.',
        remediation: 'Continue monitoring as connected apps are added.',
      });
      return { findings };
    }

    // Identify apps with no session timeout (unlimited) — any session remains valid until logout
    const noTimeout = apps.filter((a) => a.SessionTimeout === null || a.SessionTimeout === 0);

    // Identify admin-pattern apps with very long or no timeouts
    const adminAppsLongTimeout = apps.filter((a) => {
      const isAdminLike = ADMIN_APP_PATTERNS.some((p) => p.test(a.Name));
      const hasLongTimeout = (a.SessionTimeout === null || a.SessionTimeout === 0 || a.SessionTimeout > LONG_TIMEOUT_SECONDS);
      return isAdminLike && hasLongTimeout;
    });

    // Org-level risk: majority of apps have no timeout
    const percentNoTimeout = Math.round((noTimeout.length / apps.length) * 100);

    if (adminAppsLongTimeout.length > 0) {
      findings.push({
        id: 'high-assurance-admin-apps-long-timeout',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${adminAppsLongTimeout.length} admin-related connected app(s) have no or very long session timeout`,
        detail:
          `Salesforce High Assurance sessions require users to complete MFA within the CURRENT browser session before performing sensitive operations. Connected apps with names suggesting administrative or deployment capabilities should enforce short session timeouts (ideally ≤2 hours) to limit the window of a hijacked session. ${adminAppsLongTimeout.length} apps match admin naming patterns and have sessions that last longer than 8 hours or have no timeout.`,
        remediation:
          'Set the session timeout on admin-capability connected apps to 2 hours or less (Setup → Connected Apps → Manage → Edit Policies → Session Timeout). For Salesforce-internal admin operations, configure the app to require High Assurance session level so users must complete MFA within the active session.',
        affectedItems: adminAppsLongTimeout.map((a) => ({
          label: a.Name,
          url: setupUrl,
          note: a.SessionTimeout === null || a.SessionTimeout === 0
            ? 'No session timeout: sessions never expire'
            : `Session timeout: ${Math.round(a.SessionTimeout / 3600)}h, reduce to ≤2h`,
        })),
      });
    }

    if (noTimeout.length > 0 && noTimeout.length > apps.length / 2) {
      findings.push({
        id: 'high-assurance-widespread-no-timeout',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${noTimeout.length} of ${apps.length} connected app(s) (${percentNoTimeout}%) have no session timeout configured`,
        detail:
          `${percentNoTimeout}% of connected apps have no session timeout, meaning OAuth tokens and browser sessions can persist indefinitely. An attacker with a stolen token or session cookie can maintain persistent access without triggering any session expiry. Salesforce recommends configuring session timeouts on all connected apps.`,
        remediation:
          'Set appropriate session timeouts for all connected apps based on their sensitivity. Production apps handling sensitive data should use 2–8 hour timeouts. Development/CI apps can use longer timeouts if appropriate.',
        affectedItems: noTimeout.slice(0, 20).map((a) => ({
          label: a.Name,
          url: setupUrl,
          note: 'No session timeout: configure a timeout in Connected App policies',
        })),
      });
    }

    if (adminAppsLongTimeout.length === 0 && (noTimeout.length === 0 || noTimeout.length <= apps.length / 2)) {
      findings.push({
        id: 'high-assurance-session-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Connected app session timeouts are configured appropriately',
        detail: `${apps.length} connected app(s) reviewed. No admin-pattern apps with dangerously long or absent session timeouts were found.`,
        remediation: 'Periodically review connected app session policies as new apps are added. Consider requiring High Assurance sessions for any app used by administrators.',
      });
    }

    return { findings };
  }
}
