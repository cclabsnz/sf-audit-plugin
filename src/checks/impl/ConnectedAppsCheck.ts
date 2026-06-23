import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ConnectedAppRecord {
  Id: string;
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
  // SessionTimeout is in minutes; 0 = use org-level session timeout (may be very long)
  // SBS-DEP-006 requires access token timeout ≤ 15 minutes
  SessionTimeout: number | null;
}

export class ConnectedAppsCheck implements SecurityCheck {
  readonly id = 'connected-apps';
  readonly name = 'Connected Apps';
  readonly category = 'App Security';
  readonly description = 'Flags connected apps not restricted to admin-approved users';

  readonly populatesCache = ['connectedAppNames'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Single query fetches both access-control and session-timeout fields — no N+1 calls needed.
    const connectedApps = await ctx.soql.queryAll<ConnectedAppRecord>(
      `SELECT Id, Name, OptionsAllowAdminApprovedUsersOnly, SessionTimeout
       FROM ConnectedApplication`
    );

    const count = connectedApps.length;

    // Cache app names for DeploymentIdentityCheck and SiemIntegrationCheck — no extra query
    ctx.cache.connectedAppNames = connectedApps.map((a) => a.Name);

    // Check for apps with unrestricted user access
    const unrestrictedApps = connectedApps.filter(
      (app) => !app.OptionsAllowAdminApprovedUsersOnly
    );

    if (unrestrictedApps.length > 0) {
      findings.push({
        id: 'unrestricted-connected-apps',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unrestrictedApps.length} connected app(s) allow unrestricted user access`,
        detail:
          'Connected apps not restricted to admin-approved users can allow any org user to authorize the app, potentially exposing data.',
        remediation:
          'In each connected app settings, set "Permitted Users" to "Admin approved users are pre-authorized".',
        affectedItems: unrestrictedApps.map((app) => ({
          label: app.Name,
          url: `${baseUrl}/${app.Id}`,
        })),
      });
    } else {
      // All apps are properly restricted
      findings.push({
        id: 'restricted-connected-apps',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All connected apps restrict user access appropriately',
        detail: `All ${count} connected app(s) are configured to require admin pre-authorization.`,
        remediation: 'Continue monitoring as new connected apps are added.',
      });
    }

    // SBS-DEP-006: access token (session) timeout must be ≤ 15 minutes for CLI/integration apps.
    // SessionTimeout = 0 means the app inherits the org-level session timeout (often 2–8 hours),
    // which exceeds the 15-minute SBS requirement. Flag null/0 and values > 15 minutes.
    const longSessionApps = connectedApps.filter(
      (app) => app.SessionTimeout === null || app.SessionTimeout === 0 || app.SessionTimeout > 15
    );

    if (longSessionApps.length > 0) {
      findings.push({
        id: 'connected-apps-long-session-timeout',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${longSessionApps.length} connected app(s) do not enforce a short session timeout (SBS-DEP-006: ≤ 15 min)`,
        detail:
          'SBS-DEP-006 requires connected apps used for CLI or CI/CD to enforce access token timeouts of 15 minutes or less. Apps set to "0" inherit the org session timeout (commonly 2–8 hours), leaving stolen tokens valid far longer than necessary.',
        remediation:
          'Set SessionTimeout to 15 minutes or less on each connected app in Setup → Connected Apps → OAuth Policies. For CLI tools, also configure a refresh token validity period of 90 days or less.',
        affectedItems: longSessionApps.map((app) => ({
          label: app.Name,
          url: `${baseUrl}/${app.Id}`,
          note:
            app.SessionTimeout === null || app.SessionTimeout === 0
              ? 'No explicit timeout: inherits org default (likely > 15 min)'
              : `Session timeout: ${app.SessionTimeout} min, reduce to ≤ 15`,
        })),
      });
    } else if (count > 0) {
      findings.push({
        id: 'connected-apps-session-timeout-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All connected apps enforce session timeouts of 15 minutes or less',
        detail: `All ${count} connected app(s) have SessionTimeout ≤ 15 minutes, meeting the SBS-DEP-006 requirement.`,
        remediation: 'Continue monitoring as new connected apps are added.',
      });
    }

    return {
      findings,
      metrics: {
        connectedAppsCount: count,
      },
    };
  }
}
