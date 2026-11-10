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
    'Detects wildcard or overly broad CORS allowlist origins, which widen the set of websites whose scripts can use the org\'s APIs from a user\'s browser';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/CorsWhitelistEntries/home`;

    let rows: CorsRecord[];
    try {
      // CorsWhitelistEntry is served by the standard API; the Tooling API does not support it.
      rows = await ctx.soql.queryAll<CorsRecord>('SELECT Id, UrlPattern FROM CorsWhitelistEntry');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'cors-allowlist-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'CORS allowlist could not be read',
        detail: `The CorsWhitelistEntry query failed: ${msg}`,
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
        detail: 'No CORS allowlist entries exist, so scripts on other websites cannot use the org\'s REST-family APIs, Apex REST or Lightning Out from a user\'s browser. This setting does not affect server-to-server API access.',
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
          'A full wildcard origin lets scripts on any website use the org\'s REST APIs, Apex REST and Lightning Out from a user\'s browser and read the responses. ' +
          'These calls only work if the page supplies a session ID or OAuth access token; the allowlist entry does not provide one. ' +
          'The exception is a Lightning Out app shared with guest users, which any website can then run with guest access. ' +
          'Whatever the page does runs with the permissions of that token or session: it can read and change what that user can, within the token\'s scopes.',
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
          'A subdomain wildcard trusts every current and future subdomain of that domain. If any one of them is taken over or runs injected script, ' +
          'that script can use any Salesforce token or session available to it in the user\'s browser to read and change what that user can access. ' +
          'The entry itself exposes no stored credential.',
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
