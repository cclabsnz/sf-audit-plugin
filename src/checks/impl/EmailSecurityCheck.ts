import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OrgWideEmailRecord {
  Id: string;
  Address: string;
  DisplayName: string;
  IsAllowAllProfiles: boolean;
}

interface EmailServiceRecord {
  Id: string;
  FunctionName: string;
  IsActive: boolean;
  IsAuthenticationRequired: boolean;
}

interface EmailServiceAddressRecord {
  Id: string;
  LocalPart: string;
  EmailDomainName: string | null;
  IsActive: boolean;
  AuthorizedSenders: string | null;
}

// Wraps a query so a single inaccessible source degrades to an inconclusive finding
// rather than failing the whole check (mirrors the project-wide permission-error pattern).
async function tryQuery<T>(
  fn: () => Promise<T[]>,
  findings: Finding[],
  category: string,
  id: string,
  label: string,
): Promise<T[] | null> {
  try {
    return await fn();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    findings.push({
      id,
      category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${label} could not be read`,
      detail: `The query was not accessible: ${msg}`,
      remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
    });
    return null;
  }
}

export class EmailSecurityCheck implements SecurityCheck {
  readonly id = 'email-security';
  readonly name = 'Email Security & Spoofing';
  readonly category = 'External Connectivity';
  readonly description =
    'Flags inbound email services that accept mail from any sender or run Apex without authentication, and org-wide send-as addresses available to every profile';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const owaUrl = `${baseUrl}/lightning/setup/OrgWideEmailAddresses/home`;
    const svcUrl = `${baseUrl}/lightning/setup/EmailToApex/home`;

    // 1. Org-wide email addresses available to all profiles — any user can send "as" them.
    const owa = await tryQuery(
      () =>
        ctx.soql.queryAll<OrgWideEmailRecord>(
          'SELECT Id, Address, DisplayName, IsAllowAllProfiles FROM OrgWideEmailAddress',
        ),
      findings,
      this.category,
      'email-security-owa-inaccessible',
      'Org-wide email addresses',
    );

    if (owa) {
      const allProfiles = owa.filter((r) => r.IsAllowAllProfiles);
      if (allProfiles.length > 0) {
        findings.push({
          id: 'email-security-owa-all-profiles',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${allProfiles.length} org-wide email address(es) are available to all profiles`,
          detail:
            'An org-wide email address available to all profiles lets any user send email that appears to come from that address. This enables internal impersonation (e.g. spoofing a finance or executive sender) in phishing campaigns originating from inside the org.',
          remediation:
            'Restrict each org-wide email address to the specific profiles that legitimately need to send as it, rather than allowing all profiles.',
          affectedItems: allProfiles.map((r) => ({
            label: r.Address,
            url: owaUrl,
            note: `${r.DisplayName || 'no display name'} — restrict to specific profiles`,
          })),
        });
      } else if (owa.length > 0) {
        findings.push({
          id: 'email-security-owa-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: `${owa.length} org-wide email address(es) are scoped to specific profiles`,
          detail: 'No org-wide email address is exposed to all profiles, limiting send-as impersonation.',
          remediation: 'Continue to scope org-wide addresses to the profiles that need them.',
        });
      }
    }

    // 2. Inbound email services (Email-to-Apex) — internet-reachable Apex triggers.
    const services = await tryQuery(
      () =>
        ctx.soql.queryAll<EmailServiceRecord>(
          'SELECT Id, FunctionName, IsActive, IsAuthenticationRequired FROM EmailServicesFunction WHERE IsActive = true',
        ),
      findings,
      this.category,
      'email-security-services-inaccessible',
      'Inbound email services',
    );

    if (services && services.length > 0) {
      const unauthenticated = services.filter((s) => !s.IsAuthenticationRequired);
      if (unauthenticated.length > 0) {
        findings.push({
          id: 'email-security-services-no-auth',
          category: this.category,
          riskLevel: 'HIGH',
          title: `${unauthenticated.length} active inbound email service(s) do not require authentication`,
          detail:
            'An inbound email service that does not require authentication runs Apex on receipt of email from any sender. Attackers can invoke the handler repeatedly with crafted payloads, abusing it for spam relay, data injection, or as an unauthenticated entry point into Apex logic.',
          remediation:
            'Enable "Advanced Email Security Settings" so the service requires authentication (SPF/DKIM/TLS), and restrict accepted senders on each email address.',
          affectedItems: unauthenticated.map((s) => ({
            label: s.FunctionName,
            url: svcUrl,
            note: 'Active service accepts unauthenticated email',
          })),
        });
      } else {
        findings.push({
          id: 'email-security-services-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: `${services.length} active inbound email service(s) require authentication`,
          detail: 'All active inbound email services require authentication before running Apex.',
          remediation: 'Continue to require authentication and restrict accepted senders.',
        });
      }
    }

    // 3. Inbound email service addresses with no authorized-sender restriction.
    const addresses = await tryQuery(
      () =>
        ctx.soql.queryAll<EmailServiceAddressRecord>(
          'SELECT Id, LocalPart, EmailDomainName, IsActive, AuthorizedSenders FROM EmailServicesAddress WHERE IsActive = true',
        ),
      findings,
      this.category,
      'email-security-addresses-inaccessible',
      'Inbound email service addresses',
    );

    if (addresses && addresses.length > 0) {
      const open = addresses.filter((a) => !a.AuthorizedSenders || a.AuthorizedSenders.trim() === '');
      if (open.length > 0) {
        findings.push({
          id: 'email-security-addresses-open',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${open.length} inbound email address(es) accept mail from any sender`,
          detail:
            'An email service address with no "Accept Email From" restriction processes messages from any sender on the internet. Combined with an Apex handler, this is an unauthenticated, internet-facing input surface.',
          remediation:
            'Populate "Accept Email From" on each active email service address with the specific domains or addresses that should be allowed to send to it.',
          affectedItems: open.map((a) => ({
            label: `${a.LocalPart}${a.EmailDomainName ? '@' + a.EmailDomainName : ''}`,
            url: svcUrl,
            note: 'No authorized-sender restriction',
          })),
        });
      }
    }

    // If nothing was readable at all, the per-source inconclusive findings already explain why.
    return { findings };
  }
}
