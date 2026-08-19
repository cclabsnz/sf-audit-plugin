import { resolve as dnsResolve } from 'node:dns/promises';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { CspTrustedSite } from '@cclabsnz/sf-core';

// Domains treated as "Salesforce family" and therefore not flagged. This is a review
// heuristic to cut noise, NOT an allowlist: an attacker-controlled subdomain of a
// look-alike is not made safe by matching one of these suffixes. Any trusted URL outside
// this set is surfaced for a human to confirm it is still owned and expected.
const SALESFORCE_FAMILY_DOMAINS = [
  'salesforce.com',
  'force.com',
  'salesforce-experience.com',
  'visualforce.com',
  'documentforce.com',
  'salesforceliveagent.com',
  'sfdcstatic.com',
];

// Nameservers that indicate a domain has lapsed and been picked up by a parking /
// drop-catch provider. Heuristic: matched as substrings of the resolved NS hostnames.
// A parked trusted domain is the ForcedLeak precondition (an expired allowlisted domain
// re-registered by an attacker as an exfiltration channel).
const PARKING_NAMESERVERS = ['parkingcrew', 'sedoparking', 'bodis', 'afternic', 'dan.com'];

// Bound outbound DNS work so a large allowlist cannot fan out into hundreds of
// simultaneous lookups, and cap each individual lookup so one slow domain cannot stall
// the audit.
const DNS_CONCURRENCY = 5;
const DNS_TIMEOUT_MS = 3000;

// Outcome of resolving a single flagged domain.
type ResolveOutcome =
  | { kind: 'resolved' }
  | { kind: 'unresolvable' } // NXDOMAIN / ENOTFOUND
  | { kind: 'parked'; nameservers: string[] }
  | { kind: 'unverifiable'; reason: string }; // timeout / other DNS error

export class TrustedUrlHygieneCheck implements SecurityCheck {
  readonly id = 'trusted-url-hygiene';
  readonly name = 'Trusted URL Hygiene';
  readonly category = 'AI & Agents';
  readonly description =
    'Reviews the CSP trusted-sites allowlist for non-Salesforce domains that could be repurposed as data-exfiltration channels (the ForcedLeak pattern). With --resolve-domains, DNS-checks each domain for unresolvable or parked entries.';

  readonly dependsOnCache = ['cspTrustedSites'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const sites = ctx.cache.cspTrustedSites;
    // Cache absent: CspTrustedSitesCheck was skipped/failed. Nothing to review, stay silent.
    if (!sites) return { findings: [] };

    // Flag every active trusted URL whose domain is not in the Salesforce family.
    const flagged = new Map<string, CspTrustedSite>();
    for (const s of sites) {
      if (!s.isActive) continue;
      const domain = extractDomain(s.endpointUrl);
      if (!domain) continue;
      if (isSalesforceFamily(domain)) continue;
      if (!flagged.has(domain)) flagged.set(domain, s);
    }

    if (flagged.size === 0) return { findings: [] };

    const resolveDomains = ctx.options?.resolveDomains === true;
    if (!resolveDomains) {
      return { findings: [...flagged.entries()].map(([d, s]) => this.reviewFinding(d, s)) };
    }

    // --resolve-domains: DNS-check each flagged domain with bounded concurrency.
    const domains = [...flagged.keys()];
    const outcomes = await mapWithConcurrency(domains, DNS_CONCURRENCY, (d) => resolveDomain(d));

    const findings: Finding[] = [];
    domains.forEach((domain, i) => {
      const site = flagged.get(domain)!;
      const outcome = outcomes[i];
      switch (outcome.kind) {
        case 'unresolvable':
          findings.push(this.unresolvableFinding(domain, site));
          break;
        case 'parked':
          findings.push(this.parkedFinding(domain, site, outcome.nameservers));
          break;
        case 'unverifiable':
          findings.push(this.unverifiableFinding(domain, site, outcome.reason));
          break;
        case 'resolved':
          // Resolves cleanly to non-parking nameservers: still non-Salesforce, so keep the
          // review finding rather than silently passing it.
          findings.push(this.reviewFinding(domain, site));
          break;
      }
    });
    return { findings };
  }

  private reviewFinding(domain: string, site: CspTrustedSite): Finding {
    return {
      id: `trusted-url-hygiene-review-${domain}`,
      category: this.category,
      riskLevel: 'LOW',
      title: `CSP trusted site "${domain}" is a non-Salesforce domain`,
      detail:
        `The CSP trusted-sites allowlist includes "${site.endpointUrl}", whose domain "${domain}" is not ` +
        `part of the Salesforce platform. Every allowlisted domain is a place Lightning/Agentforce output can ` +
        `send data to. In the ForcedLeak incident an expired allowlisted domain was re-registered by an attacker ` +
        `and used as the exfiltration channel for prompt-injected data. Confirm this domain is still owned by a ` +
        `party you trust and is still required.`,
      remediation:
        'Verify ownership and continued need for this trusted site. Remove it if it is no longer required. ' +
        'To DNS-check the allowlist automatically, re-run with --resolve-domains.',
      affectedItems: [{ label: site.endpointUrl, note: site.context ? `Context: ${site.context}` : undefined }],
    };
  }

  private unresolvableFinding(domain: string, site: CspTrustedSite): Finding {
    return {
      id: `trusted-url-hygiene-unresolvable-${domain}`,
      category: this.category,
      riskLevel: 'CRITICAL',
      title: `CSP trusted site "${domain}" does not resolve (unregistered/expired)`,
      detail:
        `The trusted domain "${domain}" (${site.endpointUrl}) returned NXDOMAIN — it does not resolve. An ` +
        `unregistered domain on the CSP allowlist is the literal ForcedLeak precondition: anyone can register it ` +
        `and instantly gain an allowlisted exfiltration channel for data from Lightning components and Agentforce ` +
        `agent output.`,
      remediation:
        'Remove this trusted site immediately, or re-register the domain under your control if it must remain allowlisted.',
      affectedItems: [{ label: site.endpointUrl, note: site.context ? `Context: ${site.context}` : undefined }],
    };
  }

  private parkedFinding(domain: string, site: CspTrustedSite, nameservers: string[]): Finding {
    return {
      id: `trusted-url-hygiene-parked-${domain}`,
      category: this.category,
      riskLevel: 'CRITICAL',
      title: `CSP trusted site "${domain}" appears to be a parked/dropped domain`,
      detail:
        `The trusted domain "${domain}" (${site.endpointUrl}) resolves to nameservers associated with a domain ` +
        `parking / drop-catch provider (${nameservers.join(', ')}). This strongly suggests the domain lapsed and ` +
        `is no longer under your control — the ForcedLeak pattern, where an expired allowlisted domain is reused ` +
        `as an exfiltration channel.`,
      remediation:
        'Remove this trusted site immediately and reclaim the domain if it must remain allowlisted.',
      affectedItems: [{ label: site.endpointUrl, note: `Nameservers: ${nameservers.join(', ')}` }],
    };
  }

  private unverifiableFinding(domain: string, site: CspTrustedSite, reason: string): Finding {
    return {
      id: `trusted-url-hygiene-unverified-${domain}`,
      category: this.category,
      riskLevel: 'INFO',
      title: `Could not verify CSP trusted domain "${domain}"`,
      detail:
        `A DNS lookup for the trusted domain "${domain}" (${site.endpointUrl}) could not be completed (${reason}). ` +
        `This is not itself a finding — the domain may be healthy — but it could not be checked from the machine ` +
        `running the audit.`,
      remediation:
        'Re-run --resolve-domains from a network with outbound DNS, or verify the domain manually.',
      affectedItems: [{ label: site.endpointUrl, note: site.context ? `Context: ${site.context}` : undefined }],
    };
  }
}

// Extract the registrable-ish domain from a CSP endpoint URL. CSP endpoints may be bare
// hostnames, wildcards (*.example.com), or full URLs; normalise to a lowercase hostname.
export function extractDomain(endpoint: string): string | null {
  let host = endpoint.trim().toLowerCase();
  host = host.replace(/^[a-z]+:\/\//, ''); // strip scheme
  host = host.replace(/^\*\./, ''); // strip leading wildcard label
  host = host.split('/')[0]; // drop any path
  host = host.split('?')[0];
  host = host.split(':')[0]; // drop port
  host = host.replace(/\.$/, ''); // trailing dot
  return host.length > 0 ? host : null;
}

function isSalesforceFamily(domain: string): boolean {
  return SALESFORCE_FAMILY_DOMAINS.some((f) => domain === f || domain.endsWith(`.${f}`));
}

// Resolve one domain into a ResolveOutcome. Never throws: DNS errors are classified.
async function resolveDomain(domain: string): Promise<ResolveOutcome> {
  try {
    const ns = await withTimeout(dnsResolve(domain, 'NS'), DNS_TIMEOUT_MS);
    const nsHosts = (ns as string[]).map((h) => h.toLowerCase());
    const parkingHits = nsHosts.filter((h) => PARKING_NAMESERVERS.some((p) => h.includes(p)));
    if (parkingHits.length > 0) return { kind: 'parked', nameservers: nsHosts };
    return { kind: 'resolved' };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code ?? '';
    if (code === 'ENOTFOUND' || code === 'NXDOMAIN' || code === 'ENODATA') {
      // ENODATA: domain exists but has no NS answer — treat as resolved-but-unverifiable
      // only for ENODATA; NXDOMAIN/ENOTFOUND are the unregistered case.
      if (code === 'ENODATA') return { kind: 'resolved' };
      return { kind: 'unresolvable' };
    }
    const reason = code || (err instanceof Error ? err.message : String(err)) || 'DNS error';
    return { kind: 'unverifiable', reason };
  }
}

// Reject with a marker error if the wrapped promise does not settle within ms.
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEDOUT' })), ms).unref?.();
    }),
  ]);
}

// Map over items with a fixed worker pool, preserving input order in the result.
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  };
  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
