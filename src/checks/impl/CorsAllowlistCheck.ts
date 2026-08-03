import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CorsRecord {
  Id: string;
  UrlPattern: string;
}

export class CorsAllowlistCheck implements SecurityCheck {
  readonly id = 'cors-allowlist';
  readonly name = 'CORS Allowlist';
  readonly category = 'External Connectivity';
  readonly description =
    'Detects wildcard or overly broad CORS allowlist origins that let malicious sites make authenticated browser requests';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/CorsWhitelistEntries/home`;

    let rows: CorsRecord[];
    try {
      rows = await ctx.tooling.query<CorsRecord>('SELECT Id, UrlPattern FROM CorsWhitelistEntry');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'cors-allowlist-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'CORS allowlist could not be read',
        detail: `The CorsWhitelistEntry Tooling query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    if (rows.length === 0) {
      findings.push({
        id: 'cors-allowlist-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No CORS allowlist entries configured',
        detail: 'No cross-origin allowlist entries exist, so browser-based cross-origin token theft via CORS is not a concern.',
        remediation: 'If CORS entries are added later, allow only exact, fully-qualified HTTPS origins.',
      });
      return { findings };
    }

    // A pattern is a bare wildcard (https://* or *) if it has no host after the scheme.
    const isFullWildcard = (p: string): boolean => /^(https?:\/\/)?\*$/i.test(p.trim());
    // A pattern is a broad subdomain wildcard (https://*.example.com).
    const isSubdomainWildcard = (p: string): boolean => /\*\./.test(p) || /\*/.test(p);

    const wildcard = rows.filter((r) => isFullWildcard(r.UrlPattern));
    const broad = rows.filter((r) => !isFullWildcard(r.UrlPattern) && isSubdomainWildcard(r.UrlPattern));

    if (wildcard.length > 0) {
      findings.push({
        id: 'cors-wildcard-origin',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${wildcard.length} CORS allowlist entry(ies) use a full wildcard origin`,
        detail:
          'A wildcard CORS origin lets ANY website make authenticated cross-origin requests to your org from a logged-in user\'s browser and read the responses, enabling session-scoped data and token theft.',
        remediation: 'Replace wildcard origins with exact, fully-qualified HTTPS origins for each trusted application.',
        affectedItems: wildcard.map((r) => ({ label: r.UrlPattern, url: setupUrl, note: 'Full wildcard: remove immediately' })),
      });
    }

    if (broad.length > 0) {
      findings.push({
        id: 'cors-broad-origin',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${broad.length} CORS allowlist entry(ies) use a broad subdomain wildcard`,
        detail:
          'Subdomain-wildcard CORS origins trust every current and future subdomain, widening the set of sites that can make authenticated cross-origin requests. A single compromised or attacker-controlled subdomain can steal session-scoped data.',
        remediation: 'Pin CORS origins to the exact subdomains that need access rather than a wildcard.',
        affectedItems: broad.map((r) => ({ label: r.UrlPattern, url: setupUrl, note: 'Broad wildcard: narrow to exact origins' })),
      });
    }

    if (wildcard.length === 0 && broad.length === 0) {
      findings.push({
        id: 'cors-allowlist-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${rows.length} CORS allowlist entry(ies) all use exact origins`,
        detail: 'All CORS allowlist entries specify exact origins with no wildcards.',
        remediation: 'Continue to avoid wildcard CORS origins.',
      });
    }

    return { findings };
  }
}
