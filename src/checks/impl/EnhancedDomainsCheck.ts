import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OrgRecord {
  MyDomain: string | null;
  IsSandbox: boolean;
  InstanceName: string;
}

// Enhanced Domains changes the URL format for Salesforce org pages, Experience Cloud sites,
// Visualforce pages, and Lightning apps. The new format uses org-specific subdomains
// that prevent cross-org cookie and credential leakage.
//
// Pre-Enhanced: org uses shared subdomains like force.com, visualforce.com, site.com
// Post-Enhanced: all pages served from *.my.salesforce.com and *.my.site.com subdomains
//
// We detect Enhanced Domains by checking:
// 1. My Domain exists (prerequisite)
// 2. The instance URL uses the enhanced domain format (contains .my.salesforce.com or .develop.my.salesforce.com)
// 3. Org is not still on a shared instance URL like na1.salesforce.com
const ENHANCED_DOMAIN_PATTERN = /\.my\.salesforce\.com|\.sandbox\.my\.salesforce\.com|\.develop\.my\.salesforce\.com|\.scratch\.my\.salesforce\.com/i;
const LEGACY_INSTANCE_PATTERN = /^https:\/\/[a-z]{2}\d+\.salesforce\.com/i;

export class EnhancedDomainsCheck implements SecurityCheck {
  readonly id = 'enhanced-domains';
  readonly name = 'Enhanced Domains';
  readonly category = 'Authentication';
  readonly description = 'Verifies Enhanced Domains is enabled: prevents cross-org cookie leakage and enables org-specific URL isolation (required since Spring 2023)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const domainSetupUrl = `${baseUrl}/lightning/setup/MyDomain/home`;

    const orgResult = await ctx.soql.query<OrgRecord>(
      `SELECT MyDomain, IsSandbox, InstanceName FROM Organization LIMIT 1`
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

    const { MyDomain: myDomain, IsSandbox: isSandbox } = org;
    const instanceUrl = baseUrl;

    // Check if Enhanced Domains is active based on the instance URL format
    const hasEnhancedDomainUrl = ENHANCED_DOMAIN_PATTERN.test(instanceUrl);
    const hasLegacyUrl = LEGACY_INSTANCE_PATTERN.test(instanceUrl);
    const hasMyDomain = !!myDomain;

    if (!hasMyDomain) {
      findings.push({
        id: 'enhanced-domains-no-my-domain',
        category: this.category,
        riskLevel: isSandbox ? 'MEDIUM' : 'HIGH',
        title: 'My Domain is not configured: Enhanced Domains cannot be enabled',
        detail:
          `Enhanced Domains (required for production orgs since Spring 2023) depends on My Domain being configured first. Without My Domain, the org uses shared Salesforce infrastructure URLs, which means cookies and sessions are not isolated to this specific org, increasing the risk of cross-org credential leakage. My Domain also enables SSO, Lightning Experience, and granular login policies.`,
        remediation:
          'Configure My Domain in Setup → My Domain. After testing, deploy to all users. Then enable Enhanced Domains in Setup → My Domain → Enable Enhanced Domains.',
        affectedItems: [{ label: 'My Domain Setup', url: domainSetupUrl, note: 'Configure My Domain as a prerequisite for Enhanced Domains' }],
      });
      return { findings };
    }

    if (hasEnhancedDomainUrl) {
      findings.push({
        id: 'enhanced-domains-enabled',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `Enhanced Domains is active: org uses isolated subdomain (${myDomain})`,
        detail:
          `The org instance URL (${instanceUrl}) uses the Enhanced Domain format, confirming that Enhanced Domains is enabled. This means Visualforce pages, Experience Cloud sites, and Lightning apps are served from org-specific subdomains, preventing cross-org cookie leakage and improving URL isolation between Salesforce customers on shared infrastructure.`,
        remediation: 'Verify that any hardcoded legacy URLs (force.com, visualforce.com, site.com) in integrations, bookmarks, or email templates have been updated to the new Enhanced Domain URLs.',
      });
    } else if (hasLegacyUrl || !hasEnhancedDomainUrl) {
      findings.push({
        id: 'enhanced-domains-not-detected',
        category: this.category,
        riskLevel: isSandbox ? 'LOW' : 'MEDIUM',
        title: `Enhanced Domains may not be enabled: org URL appears to use a legacy format`,
        detail:
          `The org instance URL (${instanceUrl}) does not match the Enhanced Domain URL pattern (*.my.salesforce.com). The org has My Domain (${myDomain}) but may not have completed the Enhanced Domains migration. Enhanced Domains was required for all production orgs as of Spring 2023 and provides critical URL isolation that prevents cross-org cookie leakage.`,
        remediation:
          'Enable Enhanced Domains in Setup → My Domain → Enable Enhanced Domains. Review Salesforce release notes for your org edition to confirm Enhanced Domains is available and required. Update any hardcoded legacy URLs after migration.',
        affectedItems: [{
          label: myDomain,
          url: domainSetupUrl,
          note: `Instance URL: ${instanceUrl} (expected *.my.salesforce.com format)`,
        }],
      });
    }

    return { findings };
  }
}
