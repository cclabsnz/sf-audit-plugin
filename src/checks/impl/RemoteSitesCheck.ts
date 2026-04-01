import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface RemoteProxyRecord {
  Id: string;
  SiteName: string;
  EndpointUrl: string;
  IsActive: boolean;
  DisableProtocolSecurity: boolean;
}

export class RemoteSitesCheck implements SecurityCheck {
  readonly id = 'remote-sites';
  readonly name = 'Remote Site Settings';
  readonly category = 'External Connectivity';
  readonly description = 'Inventories remote site settings and flags those with protocol security disabled';

  readonly populatesCache = ['remoteSiteUrls'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SecurityRemoteProxy/home`;

    // Query active remote site settings using Tooling API
    const records = await ctx.tooling.query<RemoteProxyRecord>(
      'SELECT Id, SiteName, EndpointUrl, IsActive, DisableProtocolSecurity FROM RemoteProxy WHERE IsActive = true'
    );

    const count = records.length;

    // Cache the URLs for use by HardcodedCredentialsCheck
    ctx.cache.remoteSiteUrls = records.map((r) => r.EndpointUrl);

    // Flag sites with protocol security disabled — these allow insecure HTTP callouts
    const insecureSites = records.filter((r) => r.DisableProtocolSecurity);
    const secureSites = records.filter((r) => !r.DisableProtocolSecurity);

    if (insecureSites.length > 0) {
      findings.push({
        id: 'remote-sites-protocol-security-disabled',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${insecureSites.length} remote site(s) have protocol security disabled`,
        detail:
          'Remote sites with "Disable Protocol Security" enabled allow Apex to make callouts over plain HTTP, exposing data in transit to interception.',
        remediation:
          'Enable HTTPS on each endpoint and remove the "Disable Protocol Security" flag. Plaintext HTTP callouts should never be used for any integration.',
        affectedItems: insecureSites.map((r) => ({
          label: r.SiteName,
          url: setupUrl,
          note: `${r.EndpointUrl} — enable HTTPS and re-enable protocol security`,
        })),
      });
    }

    // Emit an inventory finding (INFO) for all active sites
    if (count > 0) {
      findings.push({
        id: 'remote-sites-inventory',
        category: this.category,
        riskLevel: insecureSites.length === 0 ? 'LOW' : 'INFO',
        title: `${count} active remote site setting(s) registered (${insecureSites.length} insecure, ${secureSites.length} secure)`,
        detail:
          'Remote Site Settings control which external URLs Apex code can call. Entries should be reviewed periodically to remove unused entries.',
        remediation:
          'Audit each remote site setting to confirm it is still actively used. Remove unused entries to reduce the attack surface.',
        affectedItems: records.map((r) => ({
          label: r.SiteName,
          url: setupUrl,
          note: `${r.EndpointUrl}${r.DisableProtocolSecurity ? ' ⚠ Protocol security disabled' : ''}`,
        })),
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
        insecureRemoteSitesCount: insecureSites.length,
      },
    };
  }
}
