import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OrgRecord {
  IsSandbox: boolean;
  InstanceName: string;
}

// Organization has no MyDomain field. Every org's My Domain is the subdomain of its instance URL
// (<name>.my.salesforce.com, or a sandbox/develop/scratch variant); a legacy instance host such as
// na1.salesforce.com means no My Domain.
const MY_DOMAIN_HOST = /^(.+?)\.(?:(?:sandbox|develop|scratch|trailblaze)\.)?my\.(?:salesforce\.com|salesforce\.mil|sfcrmproducts\.cn)$/i;

function myDomainOf(instanceUrl: string): string | null {
  let host = instanceUrl;
  try {
    host = new URL(instanceUrl).hostname;
  } catch {
    // keep the raw string
  }
  return MY_DOMAIN_HOST.exec(host)?.[1] ?? null;
}

// Enhanced domains put the org's My Domain name in every URL it serves (Experience Cloud sites,
// Salesforce Sites, Visualforce, content files). Salesforce enforced them in Winter '24, and
// legacy-hostname redirections stopped in production in Spring '26.
// https://help.salesforce.com/s/articleView?id=sf.domain_name_enhanced.htm&type=5
//
// The instance URL cannot tell: it is <name>.my.salesforce.com with or without enhanced domains.
// MyDomainSettings can. Its myDomainSuffix distinguishes MySalesforce ("my.salesforce.com with
// enhanced domains") from MySalesforceLimited ("without enhanced domains"), and a partitioned
// domainPartition (sandbox, develop, scratch, ...) requires enhanced domains.
// https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_mydomainsettings.htm
interface MyDomainSettingsMeta {
  myDomainSuffix?: string;
  domainPartition?: string;
}

const ENHANCED_SUFFIXES = new Set(['MySalesforce']);
// Only MySalesforceLimited is documented as "without enhanced domains"; other *Limited suffixes are
// left unverified rather than inferred.
const NOT_ENHANCED_SUFFIXES = new Set(['MySalesforceLimited']);

export class EnhancedDomainsCheck implements SecurityCheck {
  readonly id = 'enhanced-domains';
  readonly name = 'Enhanced Domains';
  readonly category = 'Authentication';
  readonly description = "Verifies Enhanced Domains is enabled, from MyDomainSettings: org-specific URLs for every page the org serves (enforced since Winter '24)";

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const domainSetupUrl = `${baseUrl}/lightning/setup/MyDomain/home`;

    const orgResult = await ctx.soql.query<OrgRecord>(
      `SELECT IsSandbox, InstanceName FROM Organization LIMIT 1`
    );
    const org = orgResult.records[0];

    if (!org) {
      findings.push({
        id: 'enhanced-domains-org-unreadable',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Organization settings could not be read',
        detail: 'The Organization object query returned no results.',
        remediation: 'Verify the audit user has read access to the Organization object.',
      });
      return { findings };
    }

    const { IsSandbox: isSandbox } = org;
    const myDomain = myDomainOf(baseUrl);
    const instanceUrl = baseUrl;

    if (!myDomain) {
      findings.push({
        id: 'enhanced-domains-no-my-domain',
        category: this.category,
        riskLevel: isSandbox ? 'MEDIUM' : 'HIGH',
        title: 'My Domain is not configured: Enhanced Domains cannot be enabled',
        detail:
          `Enhanced Domains (enforced since Winter '24) depends on My Domain being configured first. Without My Domain, the org uses shared Salesforce infrastructure URLs, which means cookies and sessions are not isolated to this specific org, increasing the risk of cross-org credential leakage. My Domain also enables SSO, Lightning Experience, and granular login policies.`,
        remediation:
          'Configure My Domain in Setup → My Domain. After testing, deploy to all users. Then enable Enhanced Domains in Setup → My Domain → Enable Enhanced Domains.',
        affectedItems: [{ label: 'My Domain Setup', url: domainSetupUrl, note: 'Configure My Domain as a prerequisite for Enhanced Domains' }],
      });
      return { findings };
    }

    // Read MyDomainSettings. A missing client, a failed read or an unrecognised value leaves the
    // answer unknown, which is reported as such rather than as a pass.
    let settings: MyDomainSettingsMeta | null = null;
    let readError = 'this run has no Metadata API client';
    if (ctx.metadata) {
      try {
        settings = await ctx.metadata.read<MyDomainSettingsMeta>('MyDomainSettings', 'MyDomain');
        if (!settings) readError = 'the My Domain settings were not returned';
      } catch (err) {
        readError = err instanceof Error ? err.message : String(err);
      }
    }
    const suffix = settings?.myDomainSuffix;
    const partition = settings?.domainPartition;
    const partitioned = !!partition && partition.toLowerCase() !== 'none';
    const enhanced =
      settings === null
        ? undefined
        : (suffix !== undefined && ENHANCED_SUFFIXES.has(suffix)) || partitioned
          ? true
          : suffix !== undefined && NOT_ENHANCED_SUFFIXES.has(suffix)
            ? false
            : undefined;

    if (enhanced === true) {
      findings.push({
        id: 'enhanced-domains-enabled',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `Enhanced Domains is active (${myDomain})`,
        detail: partitioned && !(suffix && ENHANCED_SUFFIXES.has(suffix))
          ? `MyDomainSettings shows a partitioned domain (${partition}), which requires enhanced domains, so URLs across the org carry the My Domain name.`
          : `MyDomainSettings reports the My Domain suffix ${suffix} (my.salesforce.com with enhanced domains), so URLs across the org, including Experience Cloud sites, Visualforce pages and content files, carry the My Domain name.`,
        remediation: 'Verify that any hardcoded legacy URLs (force.com, visualforce.com, site.com) in integrations, bookmarks, or email templates have been updated; legacy-hostname redirections have stopped.',
      });
    } else if (enhanced === false) {
      findings.push({
        id: 'enhanced-domains-not-detected',
        category: this.category,
        riskLevel: isSandbox ? 'LOW' : 'MEDIUM',
        title: 'Enhanced Domains is not enabled',
        detail:
          `MyDomainSettings reports the My Domain suffix ${suffix}, which Salesforce documents as a domain without enhanced domains. Enhanced domains were enforced in Winter '24 and legacy-hostname redirections have stopped, so URLs on the old format may already be failing, and pages are not isolated under the org's own My Domain name.`,
        remediation:
          'Enable and deploy Enhanced Domains in Setup → My Domain, then update any hardcoded legacy URLs in integrations, email templates and bookmarks.',
        affectedItems: [{ label: myDomain, url: domainSetupUrl, note: `myDomainSuffix: ${suffix}` }],
      });
    } else {
      findings.push({
        id: 'enhanced-domains-unverified',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Enhanced Domains status could not be confirmed',
        detail: settings === null
          ? `Whether Enhanced Domains is on is read from MyDomainSettings in the Metadata API, and could not be: ${readError}. The instance URL (${instanceUrl}) does not show it, because it has the same format with or without enhanced domains. Salesforce enforced enhanced domains in Winter '24.`
          : `MyDomainSettings returned a My Domain suffix (${suffix ?? 'none'}) that this check does not map to enhanced or legacy domains. Salesforce enforced enhanced domains in Winter '24.`,
        remediation: 'Confirm in Setup → My Domain that the My Domain details show enhanced domains as enabled. Ensure the audit user has "View Setup and Configuration".',
        affectedItems: [{ label: myDomain, url: domainSetupUrl }],
      });
    }

    return { findings };
  }
}
