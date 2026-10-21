import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ContentDistributionRecord {
  Id: string;
  Name: string;
  ContentDocumentId: string;
  ExpiryDate: string | null;
  PreferencesExpires: boolean;
  PreferencesPasswordRequired: boolean;
  CreatedDate: string;
}

/** Live links read per run. A full page means more exist, so the result is partial. */
const LINK_LIMIT = 500;

/** A link expires only when PreferencesExpires is set; ExpiryDate alone is not enforced. */
const expires = (r: ContentDistributionRecord): boolean => r.PreferencesExpires && Boolean(r.ExpiryDate);

// Links older than this with no expiry date are considered stale (SBS-FILE-003)
const STALE_DAYS = 90;

export class ContentLinksCheck implements SecurityCheck {
  readonly id = 'content-links';
  readonly name = 'Content Distribution Links';
  readonly category = 'File Security';
  readonly description = 'SBS-FILE-001/002/003: audits public content links for missing expiry, missing passwords, and stale records';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Single query — fetches all data needed for FILE-001 (no expiry),
    // FILE-002 (no password), and FILE-003 (stale links).
    let records: ContentDistributionRecord[];
    let truncated = false;
    try {
      // Every ContentDistribution is a public link (there is no IsPublic field). Links already past
      // their expiry no longer serve the file, so they are excluded in the query, before the LIMIT:
      // filtering after it could fill the page with dead links and hide live ones.
      const now = Date.now();
      const nowLiteral = new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z');
      const all = await ctx.soql.queryAll<ContentDistributionRecord>(
        `SELECT Id, Name, ContentDocumentId, ExpiryDate, PreferencesExpires, PreferencesPasswordRequired, CreatedDate
         FROM ContentDistribution
         WHERE (PreferencesExpires = false OR ExpiryDate = null OR ExpiryDate > ${nowLiteral})
         ORDER BY CreatedDate ASC
         LIMIT ${LINK_LIMIT}`
      );
      truncated = all.length >= LINK_LIMIT;
      records = all.filter((r) => !(expires(r) && new Date(r.ExpiryDate as string).getTime() < now));
    } catch (err) {
      findings.push({
        id: 'content-links-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Content distribution links could not be queried',
        detail:
          `SBS-FILE-001/002/003 require review of public content distribution links. The ContentDistribution query failed: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user read access to ContentDistribution records to enable this check.',
      });
      return { findings };
    }

    if (truncated) {
      // MN-051: links past the page were not read, so a clean result here proves nothing about them.
      findings.push({
        id: 'content-links-partial',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `Only the oldest ${LINK_LIMIT} live public content links were reviewed`,
        detail: `The org has more than ${LINK_LIMIT} live public content distribution links. Findings below cover the oldest ${LINK_LIMIT}; newer links were not reviewed, so their absence from a finding is not a pass.`,
        remediation: 'Review public links in Setup or with a report on Content Deliveries, and expire or delete the ones no longer needed.',
      });
    }

    if (records.length === 0) {
      findings.push({
        id: 'content-links-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active public content distribution links found',
        detail: 'SBS-FILE-001/002/003 govern the lifecycle of public content sharing links. No active public links were found in this org.',
        remediation: 'Continue monitoring as files are shared externally.',
      });
      return { findings };
    }

    const staleThreshold = new Date(Date.now() - STALE_DAYS * 86_400_000);
    const noExpiry = records.filter((r) => !expires(r));
    const noPassword = records.filter((r) => !r.PreferencesPasswordRequired);
    const stale = records.filter(
      (r) => !expires(r) && new Date(r.CreatedDate) < staleThreshold
    );

    let hasPositiveFinding = false;

    // SBS-FILE-001: all public content links must have an expiry date
    if (noExpiry.length > 0) {
      hasPositiveFinding = true;
      findings.push({
        id: 'content-links-no-expiry',
        category: this.category,
        riskLevel: noExpiry.length > 20 ? 'HIGH' : 'MEDIUM',
        title: `${noExpiry.length} public content link(s) have no expiry date: SBS-FILE-001`,
        detail:
          'SBS-FILE-001 requires all public content distribution links to have an expiry date. Links without expiry remain active indefinitely, allowing anyone with the URL to continue accessing potentially sensitive documents even after the sharing purpose has ended.',
        remediation:
          'Set an expiry date on all active public links. Establish a policy requiring expiry dates when creating new content distribution links, and configure Salesforce to enforce expiry via the Content Distribution settings.',
        affectedItems: noExpiry.slice(0, 50).map((r) => ({
          label: r.Name,
          url: `${baseUrl}/${r.ContentDocumentId}`,
          note: `created: ${new Date(r.CreatedDate).toISOString().split('T')[0]}, set an expiry date`,
        })),
      });
    }

    // SBS-FILE-002: links sharing sensitive content should be password-protected
    if (noPassword.length > 0) {
      hasPositiveFinding = true;
      findings.push({
        id: 'content-links-no-password',
        category: this.category,
        riskLevel: 'LOW',
        title: `${noPassword.length} public content link(s) are not password-protected: SBS-FILE-002`,
        detail:
          'SBS-FILE-002 recommends password-protecting public content sharing links, particularly for documents containing sensitive or confidential information. Links without a password can be accessed by anyone with the URL.',
        remediation:
          'Enable password protection for public content links that share sensitive content. Review each link to determine if the shared content warrants the additional protection layer.',
        affectedItems: noPassword.slice(0, 50).map((r) => ({
          label: r.Name,
          url: `${baseUrl}/${r.ContentDocumentId}`,
          note: `created: ${new Date(r.CreatedDate).toISOString().split('T')[0]}, assess whether password protection is needed`,
        })),
      });
    }

    // SBS-FILE-003: stale links (no expiry + older than threshold) must be cleaned up
    if (stale.length > 0) {
      hasPositiveFinding = true;
      findings.push({
        id: 'content-links-stale',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${stale.length} public content link(s) are over ${STALE_DAYS} days old with no expiry: SBS-FILE-003`,
        detail:
          `SBS-FILE-003 requires periodic cleanup of public content sharing links. ${stale.length} link(s) were created more than ${STALE_DAYS} days ago and have no expiry date, meaning they have been publicly accessible indefinitely. These likely represent sharing relationships that are no longer active.`,
        remediation:
          `Review and expire or delete all content links older than ${STALE_DAYS} days where the sharing purpose is no longer active. Establish a quarterly review process for all active content distribution links.`,
        affectedItems: stale.slice(0, 50).map((r) => ({
          label: r.Name,
          url: `${baseUrl}/${r.ContentDocumentId}`,
          note: `created: ${new Date(r.CreatedDate).toISOString().split('T')[0]}, review and expire or delete`,
        })),
      });
    }

    if (!hasPositiveFinding && !truncated) {
      findings.push({
        id: 'content-links-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${records.length} public content link(s) have expiry dates configured`,
        detail: 'SBS-FILE-001 requires all public content distribution links to have expiry dates. All active public links have an expiry date set.',
        remediation: 'Continue monitoring as new content links are created. Consider enabling password protection for links sharing sensitive documents (SBS-FILE-002).',
      });
    }

    return { findings };
  }
}
