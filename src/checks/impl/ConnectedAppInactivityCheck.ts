import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LoginHistoryGroupRecord {
  Application: string;
  loginCount: number;
}

export class ConnectedAppInactivityCheck implements SecurityCheck {
  readonly id = 'connected-app-inactivity';
  readonly name = 'Inactive Connected Apps';
  readonly category = 'App Security';
  readonly description = 'Flags connected apps with no OAuth logins in the past 90 days: stale apps are unused attack surface';

  readonly dependsOnCache = ['connectedAppNames'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ConnectedApplication/home`;

    const connectedAppNames = ctx.cache.connectedAppNames ?? [];

    if (connectedAppNames.length === 0) {
      findings.push({
        id: 'connected-app-inactivity-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No connected apps to check for inactivity',
        detail: 'No connected apps were found in the org. No inactivity check is needed.',
        remediation: 'Continue monitoring as new connected apps are added.',
      });
      return { findings };
    }

    // Query OAuth login history for the last 90 days, grouped by application name.
    // Apps NOT appearing in this result have had zero OAuth logins in 90 days. LoginHistory records
    // an OAuth login as LoginType 'Remote Access 2.0' (or 'Remote Access Client'), and the flow in
    // LoginSubType ('OAuth Web Server', 'OAuth Refresh Token', 'OAuth JWT Bearer', ...). No
    // LoginType starts with 'OAuth', so filtering on that found no logins and called every app inactive.
    let activeAppNames = new Set<string>();
    try {
      const result = await ctx.soql.query<LoginHistoryGroupRecord>(
        `SELECT Application, COUNT(Id) loginCount
         FROM LoginHistory
         WHERE LoginTime > LAST_N_DAYS:90
           AND (LoginType IN ('Remote Access 2.0', 'Remote Access Client') OR LoginSubType LIKE 'OAuth%')
         GROUP BY Application`
      );
      for (const r of result.records) {
        if (r.Application) activeAppNames.add(r.Application.toLowerCase());
      }
    } catch {
      findings.push({
        id: 'connected-app-inactivity-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Connected app activity could not be determined: LoginHistory not accessible',
        detail: 'LoginHistory was not accessible. Connected app inactivity cannot be computed without login history.',
        remediation: 'Grant LoginHistory read access to the audit user.',
      });
      return { findings };
    }

    // Case-insensitive match between ConnectedApp names and LoginHistory Application names
    const inactiveApps = connectedAppNames.filter(
      (name) => !activeAppNames.has(name.toLowerCase())
    );
    const activeApps = connectedAppNames.filter(
      (name) => activeAppNames.has(name.toLowerCase())
    );

    if (inactiveApps.length > 0) {
      findings.push({
        id: 'connected-app-inactive',
        category: this.category,
        riskLevel: inactiveApps.length > 5 ? 'MEDIUM' : 'LOW',
        title: `${inactiveApps.length} connected app(s) have had no OAuth logins in 90 days`,
        detail:
          `${inactiveApps.length} of ${connectedAppNames.length} connected apps show no OAuth login activity in the past 90 days. Inactive apps still hold valid OAuth credentials and expand the attack surface. A compromised or leaked client secret for an inactive app can be used to obtain access tokens without triggering activity alerts.`,
        remediation:
          "Confirm with the app's owner whether the integration is still needed, and check Setup → Connected Apps OAuth Usage for tokens still held. If it is not needed, revoke its tokens and set Permitted Users to \"Admin approved users are pre-authorized\" with no profiles or permission sets assigned, which stops it being used. Delete it only once you are sure: a delete cannot be undone, it destroys the consumer key and secret, and new connected apps cannot be created from Spring '26.",
        affectedItems: inactiveApps.map((name) => ({
          label: name,
          url: setupUrl,
          note: 'No OAuth logins in 90 days: confirm it is still needed',
        })),
      });
    }

    if (activeApps.length > 0) {
      findings.push({
        id: 'connected-app-active',
        category: this.category,
        riskLevel: 'INFO',
        title: `${activeApps.length} connected app(s) have active OAuth logins`,
        detail: `${activeApps.length} connected app(s) show recent OAuth login activity in the past 90 days.`,
        remediation: 'Periodically review active connected apps to ensure all have documented owners and business justification.',
        affectedItems: activeApps.map((name) => ({
          label: name,
          url: setupUrl,
          note: 'Active: verify documented owner and justification',
        })),
      });
    }

    return { findings };
  }
}
