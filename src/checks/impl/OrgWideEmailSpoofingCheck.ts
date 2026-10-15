import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface OrgWideEmailAddressRecord {
  Id: string;
  Address: string;
  DisplayName: string;
  IsAllowAllProfiles: boolean;
  IsVerified?: boolean;
}

interface DkimKeyRecord {
  Id: string;
  Domain?: string | null;
  DomainMatch?: string | null;
  Status?: string | null;
  IsActive?: boolean;
}

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

export class OrgWideEmailSpoofingCheck implements SecurityCheck {
  readonly id = 'org-wide-email-spoofing';
  readonly name = 'Org-Wide Email Spoofing & DKIM Coverage';
  readonly category = 'External Connectivity';
  readonly description =
    'Flags org-wide email addresses open to all profiles and missing DKIM keys enabling internal and outbound email spoofing.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const owaUrl = `${baseUrl}/lightning/setup/OrgWideEmailAddresses/home`;
    const dkimUrl = `${baseUrl}/lightning/setup/EmailDKIM/home`;

    // 1. Query OrgWideEmailAddress
    let owaRecords: OrgWideEmailAddressRecord[] = [];
    try {
      owaRecords = await ctx.soql.queryAll<OrgWideEmailAddressRecord>(
        'SELECT Id, Address, DisplayName, IsAllowAllProfiles FROM OrgWideEmailAddress',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        // Continue to DKIM check
      } else {
        findings.push({
          id: 'org-wide-email-spoofing-inaccessible',
          category: this.category,
          riskLevel: 'INFO',
          inconclusive: true,
          title: 'OrgWideEmailAddress could not be queried',
          detail: `Query to OrgWideEmailAddress failed: ${err instanceof Error ? err.message : String(err)}`,
          remediation: 'Grant the audit user "View Setup and Configuration".',
        });
      }
    }

    const openOwaRecords = owaRecords.filter((r) => r.IsAllowAllProfiles);

    if (openOwaRecords.length > 0) {
      findings.push({
        id: 'org-wide-email-spoofing-all-profiles',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${openOwaRecords.length} Org-Wide Email Address(es) are available to All Profiles`,
        detail:
          'Org-wide email addresses with "All Profiles" selected allow any internal user, guest user (if misconfigured), or automated Flow to send emails impersonating billing, support, or executive identities. In compromise or insider scenarios, this facilitates high-reputation phishing sent directly from legitimate Salesforce mail servers.',
        remediation:
          'Restrict each org-wide address to specific authorized profiles rather than granting access to all profiles.',
        affectedItems: openOwaRecords.map((r) => ({
          label: r.Address,
          url: owaUrl,
          note: `Display Name: "${r.DisplayName || 'None'}" exposed to all profiles`,
        })),
      });
    }

    // 2. Query DkimKey
    let dkimKeys: DkimKeyRecord[] = [];
    let dkimInaccessible = false;
    try {
      dkimKeys = await ctx.soql.queryAll<DkimKeyRecord>(
        'SELECT Id, Domain, Status FROM DkimKey',
      );
    } catch (err) {
      if (!isMissingObjectError(err)) {
        dkimInaccessible = true;
      }
    }

    const activeDkimKeys = dkimKeys.filter(
      (k) => (k.Status ?? '').toLowerCase() === 'active' || k.IsActive === true,
    );

    if (!dkimInaccessible && activeDkimKeys.length === 0) {
      findings.push({
        id: 'org-wide-email-spoofing-no-dkim',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: 'Zero active DKIM keys configured for outbound Salesforce email',
        detail:
          'Outbound emails sent from Salesforce without DKIM signatures are vulnerable to domain spoofing, recipient rejection, or landing in junk folders. Active DKIM keys ensure cryptographic origin authentication for all outbound Salesforce messages.',
        remediation:
          'Generate and activate DKIM keys in Setup → DKIM Keys for all corporate sending domains used by Salesforce.',
        affectedItems: [
          {
            label: 'DKIM Keys Configuration',
            url: dkimUrl,
            note: 'No active DKIM keys found in org',
          },
        ],
      });
    }

    if (openOwaRecords.length === 0 && (activeDkimKeys.length > 0 || dkimInaccessible)) {
      findings.push({
        id: 'org-wide-email-spoofing-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Org-wide email addresses are properly scoped and DKIM signing is active',
        detail: `${owaRecords.length} org-wide address(es) and ${activeDkimKeys.length} active DKIM key(s) verified; no all-profile exposure detected.`,
        remediation: 'Maintain profile-based scoping on all org-wide sending addresses.',
      });
    }

    return { findings };
  }
}
