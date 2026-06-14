import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { AuditContext } from '../../context/AuditContext.js';

interface CspTrustedSite {
  Id: string;
  EndpointUrl: string;
  Context: string;
  IsActive: boolean;
}

export class CspTrustedSitesCheck implements SecurityCheck {
  readonly id       = 'csp-trusted-sites';
  readonly name     = 'CSP Trusted Sites';
  readonly category = 'Network Security';
  readonly description =
    'Checks Content Security Policy trusted sites for insecure HTTP endpoints that allow mixed-content loading.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const sites = await ctx.soql.queryAll<CspTrustedSite>(
      `SELECT Id, EndpointUrl, Context, IsActive FROM CspTrustedSite WHERE IsActive = true`,
    );

    if (sites.length === 0) {
      return {
        findings: [{
          id: 'csp-trusted-sites-none',
          category: this.category,
          riskLevel: 'INFO',
          passed: true,
          title: 'No active CSP Trusted Sites configured',
          detail:
            'No active CSP Trusted Sites are configured. Salesforce applies default Content Security Policy headers. Add trusted sites only when loading external resources in Lightning components.',
          remediation:
            'No action required. When adding external resources, use HTTPS endpoints only.',
        }],
      };
    }

    const insecure = sites.filter((s) => s.EndpointUrl.toLowerCase().startsWith('http://'));

    if (insecure.length === 0) {
      return {
        findings: [{
          id: 'csp-trusted-sites-pass',
          category: this.category,
          riskLevel: 'INFO',
          title: `CSP Trusted Sites: all ${sites.length} active entries use HTTPS`,
          detail: `All ${sites.length} active CSP trusted site(s) use secure HTTPS endpoints.`,
          remediation: 'No action required.',
          passed: true,
        }],
      };
    }

    return {
      findings: [{
        id: 'csp-trusted-sites-insecure',
        category: this.category,
        riskLevel: 'HIGH',
        title: `CSP Trusted Sites: ${insecure.length} insecure HTTP endpoint(s)`,
        detail:
          `${insecure.length} of ${sites.length} active CSP Trusted Site(s) use unencrypted HTTP URLs. ` +
          `These allow mixed-content loading, enabling man-in-the-middle attacks where injected scripts ` +
          `can execute in the Salesforce Lightning context.`,
        remediation:
          'Update each affected CSP Trusted Site to use HTTPS. ' +
          'Navigate to Setup → Security → CSP Trusted Sites and edit each entry.',
        affectedItems: insecure.map((s) => ({
          label: s.EndpointUrl,
          note: `Context: ${s.Context}`,
          url: `${ctx.orgInfo.instanceUrl}/lightning/setup/ContentSecurityPolicy/home`,
        })),
      }],
    };
  }
}
