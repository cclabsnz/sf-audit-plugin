import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkRecord {
  Id: string;
  Name: string;
  Status: string;
  UrlPathPrefix: string | null;
  SelfRegProfileId: string | null;
  GuestUserId: string | null;
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
        `SELECT Id, Name, Status, UrlPathPrefix, SelfRegProfileId, GuestUserId
         FROM Network
         WHERE Status = 'Live'`,
      );
    } catch {
      findings.push({
        id: 'experience-cloud-site-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Experience Cloud site configuration could not be queried',
        detail:
          'The Network SOQL query was not accessible. This may indicate the audit user lacks access to Experience Cloud configuration or no sites are provisioned.',
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
    const guestSites = networks.filter((n) => n.GuestUserId !== null);

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

    if (selfRegSites.length === 0 && guestSites.length === 0) {
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
