import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkRecord {
  Id: string;
  Name: string;
  Status: string;
  UrlPathPrefix: string | null;
  SelfRegProfileId: string | null;
}

interface SiteRecord {
  MasterLabel: string | null;
  UrlPathPrefix: string | null;
  GuestUserId: string | null;
  GuestUser: { IsActive: boolean } | null;
}

/**
 * Network has no guest-user field: each Experience site's guest user is on its Site record
 * (SiteType ChatterNetwork, or ChatterNetworkPicasso for Experience Builder sites). Site carries
 * no network id, so a Site belongs to a network when its label is the network's name, or its path
 * prefix is the network's, the network's followed by "/s", or (LWR sites) followed by "vforcesite".
 */
function siteBelongsTo(site: SiteRecord, network: NetworkRecord): boolean {
  if (site.MasterLabel && site.MasterLabel === network.Name) return true;
  const net = network.UrlPathPrefix ?? '';
  const sp = site.UrlPathPrefix ?? '';
  return sp === net || sp === (net === '' ? 's' : `${net}/s`) || sp === `${net}vforcesite`;
}

export class ExperienceCloudSiteCheck implements SecurityCheck {
  readonly id = 'experience-cloud-site';
  readonly name = 'Experience Cloud Site Security';
  readonly category = 'Access Control';
  readonly description =
    'Checks live Experience Cloud sites for self-registration enabled (attacker account creation) and guest user presence';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SetupNetworks/home`;

    let networks: NetworkRecord[];
    try {
      networks = await ctx.soql.queryAll<NetworkRecord>(
        `SELECT Id, Name, Status, UrlPathPrefix, SelfRegProfileId
         FROM Network
         WHERE Status = 'Live'`,
      );
    } catch (err) {
      findings.push({
        id: 'experience-cloud-site-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Experience Cloud site configuration could not be queried',
        detail:
          `The Network query failed: ${err instanceof Error ? err.message : String(err)}. If no Experience Cloud licence is active, this check is not applicable.`,
        remediation:
          'Grant "View Setup and Configuration" to the audit user and re-run. If no Experience Cloud licence is active, this check is not applicable.',
      });
      return { findings };
    }

    if (networks.length === 0) {
      findings.push({
        id: 'experience-cloud-site-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No live Experience Cloud sites found',
        detail: 'No publicly live Experience Cloud (Community/Portal) sites are configured in this org.',
        remediation:
          'If sites are added in the future, review self-registration settings and guest user permissions before going live.',
      });
      return { findings };
    }

    const selfRegSites = networks.filter((n) => n.SelfRegProfileId !== null);

    let sites: SiteRecord[] | null;
    try {
      sites = await ctx.soql.queryAll<SiteRecord>(
        `SELECT MasterLabel, UrlPathPrefix, GuestUserId, GuestUser.IsActive
         FROM Site
         WHERE SiteType IN ('ChatterNetwork', 'ChatterNetworkPicasso') AND Status = 'Active'`,
      );
    } catch {
      sites = null;
    }
    const guestSites =
      sites === null
        ? []
        : networks.filter((n) =>
            sites!.some((s) => s.GuestUserId !== null && s.GuestUser?.IsActive !== false && siteBelongsTo(s, n)),
          );

    // A live network whose Site record could not be found has unknown guest access, not none.
    const unmatched = sites === null ? [] : networks.filter((n) => !sites!.some((s) => siteBelongsTo(s, n)));
    if (unmatched.length > 0) {
      findings.push({
        id: 'experience-cloud-site-guest-unknown',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `Guest access could not be determined for ${unmatched.length} live Experience Cloud site(s)`,
        detail:
          'No active Site record could be matched to these live networks by name or path prefix, so whether they allow unauthenticated access is unknown, not absent.',
        remediation: 'Review each site\'s guest user in Setup → Digital Experiences.',
        affectedItems: unmatched.map((n) => ({ label: n.Name, url: setupUrl, note: `URL prefix: ${n.UrlPathPrefix ?? '(default)'}` })),
      });
    }

    if (sites === null) {
      // Without the Site records, guest access is unknown, not absent.
      findings.push({
        id: 'experience-cloud-site-guest-unknown',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Guest access on live Experience Cloud sites could not be determined',
        detail:
          'The Site records that carry each Experience site\'s guest user could not be read, so whether these sites allow unauthenticated access is unknown.',
        remediation: 'Review each site\'s guest user in Setup → Digital Experiences, or grant "View Setup and Configuration" and re-run.',
        affectedItems: networks.map((n) => ({ label: n.Name, url: setupUrl })),
      });
    }

    if (selfRegSites.length > 0) {
      findings.push({
        id: 'experience-cloud-site-self-registration',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${selfRegSites.length} live Experience Cloud site(s) allow self-registration`,
        detail:
          'Self-registration allows anyone on the internet to create a portal account. Attackers exploit this to: (1) enumerate valid email addresses already registered; (2) create portal accounts to access any data exposed to authenticated portal users via OWD, sharing rules, or misconfigured permissions; (3) pivot from a portal user account to exploit object-level permission misconfigurations. If OWD for sensitive objects is set to Public Read or wider for external users, self-registration gives attackers direct data access without any approval step.',
        remediation:
          'Disable self-registration unless explicitly required (Setup → Digital Experiences → <site> → Administration → Registration). If required, implement email domain allow-listing, CAPTCHA, and manual approval workflows. Immediately audit external OWD settings and guest user permissions for sites with self-registration enabled.',
        affectedItems: selfRegSites.map((n) => ({
          label: n.Name,
          url: `${baseUrl}/lightning/setup/SetupNetworks/home`,
          note: `Self-registration enabled, SelfRegProfileId: ${n.SelfRegProfileId}`,
        })),
      });
    }

    if (guestSites.length > 0) {
      findings.push({
        id: 'experience-cloud-site-guest-access',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${guestSites.length} live Experience Cloud site(s) have guest (unauthenticated) access enabled`,
        detail:
          'Sites with an active Guest User allow unauthenticated visitors to access the site without creating an account. Any Salesforce objects or records accessible to the Guest User profile are exposed to the entire internet. Misconfigurations in guest user object permissions or OWD external settings result in public data exposure.',
        remediation:
          'Review guest user object permissions for each site (Setup → Profiles → <Guest Profile> → Object Settings). Ensure external OWD is Private for all sensitive objects. Run the Guest User Access check for detailed permission findings.',
        affectedItems: guestSites.map((n) => ({
          label: n.Name,
          url: setupUrl,
          note: `Guest access enabled: verify Guest Profile permissions`,
        })),
      });
    }

    if (selfRegSites.length === 0 && guestSites.length === 0 && sites !== null && unmatched.length === 0) {
      findings.push({
        id: 'experience-cloud-site-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${networks.length} live Experience Cloud site(s): no self-registration or open guest access`,
        detail: `All ${networks.length} live site(s) have self-registration disabled and no active guest users. Portal access requires an explicit user account.`,
        remediation:
          'Continue to monitor site configuration as sites are updated. Review portal user object permissions periodically.',
        affectedItems: networks.map((n) => ({
          label: n.Name,
          url: setupUrl,
          note: `URL prefix: ${n.UrlPathPrefix ?? '(default)'}`,
        })),
      });
    }

    return { findings };
  }
}
