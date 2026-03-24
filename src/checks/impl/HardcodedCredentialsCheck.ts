import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body: string;
  LengthWithoutComments: number;
  NamespacePrefix: string | null;
}

const HIGH_RISK_PATTERNS = [
  /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/gi,           // Bearer tokens
  /Basic\s+[A-Za-z0-9+/]+=*/gi,                  // Basic auth
  /Authorization['":\s]+['"](Bearer|Basic)/gi,     // Auth headers
  /'[A-Za-z0-9]{20,}'/g,                          // Long string literals (potential API keys)
];

const ENDPOINT_PATTERN = /\.setEndpoint\s*\(\s*'(https?:\/\/[^']+)'/gi;

function extractBase(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return url;
  }
}

function isCovered(rawUrl: string, endpoints: string[]): boolean {
  const base = extractBase(rawUrl);
  return endpoints.some((ep) => ep.includes(base) || base.includes(extractBase(ep)));
}

export class HardcodedCredentialsCheck implements SecurityCheck {
  readonly id = 'hardcoded-credentials';
  readonly name = 'Hardcoded Credentials';
  readonly category = 'Code Security';

  readonly dependsOnCache = ['namedCredentialEndpoints', 'remoteSiteUrls'] as const;
  readonly populatesCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    const records = await ctx.tooling.query<ApexClassRecord>(
      'SELECT Id, Name, Body, LengthWithoutComments, NamespacePrefix FROM ApexClass WHERE NamespacePrefix = null'
    );

    // Cache apex bodies for downstream checks (filter null bodies — large/restricted classes)
    ctx.cache.apexBodies = records.map((r) => ({ name: r.Name, body: r.Body ?? '' }));

    const namedCredentialEndpoints = (ctx.cache.namedCredentialEndpoints ?? []).filter(Boolean);
    const remoteSiteUrls = (ctx.cache.remoteSiteUrls ?? []).filter(Boolean);
    const allCoveredEndpoints = [...namedCredentialEndpoints, ...remoteSiteUrls];

    const classesWithCredentials: string[] = [];
    const classesWithRawEndpointsUncovered: string[] = [];
    const classesWithRawEndpointsCoveredOnly: string[] = [];

    for (const record of records) {
      const body = record.Body ?? '';

      // Check for hardcoded credential patterns
      const hasCredentials = HIGH_RISK_PATTERNS.some((pattern) => {
        pattern.lastIndex = 0;
        return pattern.test(body);
      });

      if (hasCredentials) {
        classesWithCredentials.push(record.Name);
      }

      // Find raw endpoints
      const rawEndpoints: string[] = [];
      ENDPOINT_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = ENDPOINT_PATTERN.exec(body)) !== null) {
        rawEndpoints.push(match[1]);
      }

      if (rawEndpoints.length > 0) {
        let hasUncovered = false;
        let hasCoveredOnly = false;

        for (const rawUrl of rawEndpoints) {
          const coveredByNamed = isCovered(rawUrl, namedCredentialEndpoints);
          const coveredByRemote = isCovered(rawUrl, remoteSiteUrls);

          if (!coveredByNamed && !coveredByRemote) {
            hasUncovered = true;
          } else if (!coveredByNamed && coveredByRemote) {
            hasCoveredOnly = true;
          }
        }

        if (hasUncovered) {
          classesWithRawEndpointsUncovered.push(record.Name);
        } else if (hasCoveredOnly) {
          classesWithRawEndpointsCoveredOnly.push(record.Name);
        }
      }
    }

    const total = records.length;

    if (classesWithCredentials.length > 0) {
      const count = classesWithCredentials.length;
      findings.push({
        id: 'hardcoded-credentials-found',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} Apex class(es) contain potential hardcoded credentials`,
        detail: 'Hardcoded Bearer tokens, Basic auth, or API keys in Apex source code expose credentials to anyone with metadata read access.',
        remediation: 'Replace hardcoded credentials with Named Credentials. Rotate any exposed credentials immediately.',
        affectedItems: classesWithCredentials,
      });
    }

    if (classesWithRawEndpointsUncovered.length > 0) {
      const count = classesWithRawEndpointsUncovered.length;
      findings.push({
        id: 'raw-endpoints-uncovered',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count} Apex class(es) contain raw callout endpoints not covered by Named Credentials`,
        detail: 'Raw HTTPS endpoints in setEndpoint() calls are not protected by Named Credentials, which means authentication details may be hardcoded nearby.',
        remediation: 'Migrate raw endpoints to Named Credentials to centralise credential management and reduce hardcoding.',
        affectedItems: classesWithRawEndpointsUncovered,
      });
    }

    if (classesWithRawEndpointsCoveredOnly.length > 0) {
      const count = classesWithRawEndpointsCoveredOnly.length;
      findings.push({
        id: 'raw-endpoints-remote-site-only',
        category: this.category,
        riskLevel: 'LOW',
        title: `${count} Apex class(es) use raw endpoints covered by Remote Site Settings`,
        detail: 'These classes use raw callout URLs but the endpoints are registered as Remote Sites. Consider migrating to Named Credentials for better credential management.',
        remediation: 'Named Credentials provide better security than Remote Site Settings for authenticated callouts.',
        affectedItems: classesWithRawEndpointsCoveredOnly,
      });
    }

    if (
      classesWithCredentials.length === 0 &&
      classesWithRawEndpointsUncovered.length === 0 &&
      classesWithRawEndpointsCoveredOnly.length === 0
    ) {
      findings.push({
        id: 'no-hardcoded-credentials',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No hardcoded credentials or unprotected endpoints detected in Apex classes',
        detail: `Scanned ${total} custom Apex classes. No obvious hardcoded credential patterns or unprotected callout endpoints were found.`,
        remediation: 'Continue using Named Credentials for all external callouts and periodically re-scan as new code is added.',
      });
    }

    return { findings };
  }
}
