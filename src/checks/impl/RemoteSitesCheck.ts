import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface RemoteProxyRecord {
  Id: string;
  SiteName: string;
  EndpointUrl: string;
  IsActive: boolean;
}

export class RemoteSitesCheck implements SecurityCheck {
  readonly id = 'remote-sites';
  readonly name = 'Remote Site Settings';
  readonly category = 'External Connectivity';
  readonly description = 'Inventories remote site settings and flags those not covered by Named Credentials';

  readonly populatesCache = ['remoteSiteUrls'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Query active remote site settings using Tooling API
    const records = await ctx.tooling.query<RemoteProxyRecord>(
      'SELECT Id, SiteName, EndpointUrl, IsActive FROM RemoteProxy WHERE IsActive = true'
    );

    const count = records.length;

    // Cache the URLs for use by HardcodedCredentialsCheck
    ctx.cache.remoteSiteUrls = records.map((r) => r.EndpointUrl);

    if (records.length > 0) {
      let riskLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      if (count > 10) {
        riskLevel = 'MEDIUM';
      }

      findings.push({
        id: 'remote-sites-found',
        category: this.category,
        riskLevel,
        title: `${count} active remote site setting(s) registered`,
        detail:
          'Remote Site Settings control which external URLs Apex code can call. A large number may indicate excessive external connectivity.',
        remediation:
          'Audit each remote site setting to confirm it is still actively used. Remove unused entries to reduce the attack surface.',
        affectedItems: records.map((r) => `${r.SiteName}: ${r.EndpointUrl}`),
      });
    } else {
      findings.push({
        id: 'no-remote-sites',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No active remote site settings found',
        detail:
          'No active Remote Site Settings are registered in this org.',
        remediation:
          'This is expected if the org does not make outbound callouts. Monitor as integrations are added.',
      });
    }

    return {
      findings,
      metrics: {
        remoteSitesCount: count,
      },
    };
  }
}
