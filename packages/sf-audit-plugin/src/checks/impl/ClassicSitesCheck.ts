import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface SiteRec {
  Id: string;
  Name: string;
  Status: string;
  SiteType: string;
  GuestUserId: string | null;
  MasterLabel: string | null;
}

// Classic (non-Experience-Builder) public site types. Siteforce = Experience
// Builder sites, which the Network-based guest checks already cover.
const CLASSIC_TYPES = new Set(['Visualforce', 'ChatterNetworkPicasso']);

/**
 * Audits classic Force.com Sites (Visualforce sites), a public unauthenticated
 * surface that runs in PARALLEL to Experience Cloud and is missed by the
 * Network-based guest checks. Each active classic site has its own guest user
 * whose profile can expose Apex, Visualforce pages, and objects to anonymous
 * visitors (the vector behind classic `/apex/…` public pages).
 */
export class ClassicSitesCheck implements SecurityCheck {
  readonly id = 'classic-sites';
  readonly name = 'Classic Force.com Sites';
  readonly category = 'Access Control';
  readonly description =
    'Flags active classic (Visualforce) Force.com Sites and their guest users — an unauthenticated public surface separate from Experience Cloud';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let sites: SiteRec[];
    try {
      sites = await ctx.soql.queryAll<SiteRec>(
        'SELECT Id, Name, Status, SiteType, GuestUserId, MasterLabel FROM Site',
      );
    } catch {
      findings.push({
        id: 'classic-sites-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Force.com Sites could not be queried (insufficient access)',
        detail: 'The Site object was not accessible, so classic public sites could not be evaluated. This may mean Sites is not enabled.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run. If Sites is not used, this check is not applicable.',
      });
      return { findings };
    }

    const classicActive = sites.filter((s) => CLASSIC_TYPES.has(s.SiteType) && s.Status === 'Active');

    if (classicActive.length > 0) {
      const withGuest = classicActive.filter((s) => s.GuestUserId);
      findings.push({
        id: 'classic-sites-active',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${classicActive.length} active classic (Visualforce) Force.com site(s)`,
        detail:
          `Classic Force.com Sites serve pages to unauthenticated visitors through a dedicated guest user, separate from Experience Cloud. ${withGuest.length} of these have a guest user whose profile governs anonymous access to Apex, Visualforce pages, and objects. This surface is easy to forget because the guest/Experience-Cloud checks only inspect Experience (Network) sites.`,
        remediation:
          'For each active classic site, review the guest user profile (object/field permissions, guest-executable Apex, exposed VF pages) exactly as for Experience Cloud guests. Deactivate sites that are no longer needed. Re-run guest-object-exposure/guest-executable-apex to grade the exposure of these guest users.',
        affectedItems: classicActive.slice(0, 30).map((s) => ({
          label: `${s.MasterLabel ?? s.Name} (${s.SiteType}${s.GuestUserId ? ', guest user present' : ', no guest user'})`,
          url: `${baseUrl}/lightning/setup/CustomDomains/home`,
        })),
      });
    } else {
      findings.push({
        id: 'classic-sites-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active classic Force.com sites',
        detail: 'No active Visualforce Force.com Sites were found, so there is no classic unauthenticated site surface.',
        remediation: 'If a classic site is activated later, review its guest user profile before it goes live.',
      });
    }

    return { findings };
  }
}
