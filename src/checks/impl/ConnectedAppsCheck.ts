import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ConnectedAppRecord {
  Id: string;
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
}

export class ConnectedAppsCheck implements SecurityCheck {
  readonly id = 'connected-apps';
  readonly name = 'Connected Apps';
  readonly category = 'App Security';
  readonly description = 'Flags connected apps not restricted to admin-approved users';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Query all connected applications
    const connectedApps = await ctx.soql.queryAll<ConnectedAppRecord>(
      `SELECT Id, Name, OptionsAllowAdminApprovedUsersOnly
       FROM ConnectedApplication`
    );

    const count = connectedApps.length;

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
        affectedItems: unrestrictedApps.map((app) => app.Name),
      });
    } else {
      // All apps are properly restricted
      findings.push({
        id: 'restricted-connected-apps',
        category: this.category,
        riskLevel: 'LOW',
        title: 'All connected apps restrict user access appropriately',
        detail: `All ${count} connected app(s) are configured to require admin pre-authorization.`,
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
