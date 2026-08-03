import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkRec {
  Id: string;
  Name: string;
  Status: string;
  OptionsGuestFileAccessEnabled: boolean;
  OptionsGuestMemberVisibility: boolean;
}

/**
 * Flags two Experience Cloud Network settings that widen the unauthenticated
 * guest surface and are not covered by the self-registration / guest-user checks:
 *   - OptionsGuestFileAccessEnabled: guests can access public files (ContentVersion/
 *     Attachment), enabling file enumeration and download.
 *   - OptionsGuestMemberVisibility: guests can see other site members (User records),
 *     leaking member identities to unauthenticated visitors.
 */
export class GuestSiteOptionsCheck implements SecurityCheck {
  readonly id = 'guest-site-options';
  readonly name = 'Experience Cloud Guest Site Options';
  readonly category = 'Access Control';
  readonly description =
    'Checks Experience Cloud sites for guest file access and guest member visibility, which expose files and member identities to unauthenticated visitors';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SetupNetworks/home`;

    let networks: NetworkRec[];
    try {
      networks = await ctx.soql.queryAll<NetworkRec>(
        `SELECT Id, Name, Status, OptionsGuestFileAccessEnabled, OptionsGuestMemberVisibility FROM Network`,
      );
    } catch {
      findings.push({
        id: 'guest-site-options-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Experience Cloud site options could not be queried (insufficient access)',
        detail: 'The Network query was not accessible. This may indicate no Experience Cloud licence or missing setup access.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run. If no Experience Cloud sites exist, this check is not applicable.',
      });
      return { findings };
    }

    if (networks.length === 0) {
      findings.push({
        id: 'guest-site-options-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Experience Cloud sites found',
        detail: 'No Experience Cloud (Network) sites are configured, so guest file access and member visibility are not a concern.',
        remediation: 'If sites are added later, keep guest file access and member visibility disabled unless explicitly required.',
      });
      return { findings };
    }

    const fileSites = networks.filter((n) => n.OptionsGuestFileAccessEnabled);
    const memberSites = networks.filter((n) => n.OptionsGuestMemberVisibility);

    if (fileSites.length > 0) {
      findings.push({
        id: 'guest-site-options-file-access',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${fileSites.length} site(s) allow guest users to access files`,
        detail:
          'Guest file access lets unauthenticated visitors read public files (ContentVersion/ContentDocument/Attachment). Combined with the UI API, file IDs can be enumerated and content downloaded via the file servlet (/sfc/servlet.shepherd/version/download).',
        remediation: 'Disable guest file access (Network setting "Let guest users access public files") unless a specific public file library is intended.',
        affectedItems: fileSites.map((n) => ({
          label: n.Name,
          url: setupUrl,
          note: `Status: ${n.Status}; guest file access enabled`,
        })),
      });
    }

    if (memberSites.length > 0) {
      findings.push({
        id: 'guest-site-options-member-visibility',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${memberSites.length} site(s) let guest users see other members`,
        detail:
          'Guest member visibility exposes other site members (User records, names, profile data) to unauthenticated visitors, leaking member identities and enabling enumeration.',
        remediation: 'Disable "Let guest users see other members of this site" unless member directories must be public.',
        affectedItems: memberSites.map((n) => ({
          label: n.Name,
          url: setupUrl,
          note: `Status: ${n.Status}; guest member visibility enabled`,
        })),
      });
    }

    if (fileSites.length === 0 && memberSites.length === 0) {
      findings.push({
        id: 'guest-site-options-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${networks.length} Experience Cloud site(s): guest file access and member visibility disabled`,
        detail: 'No site exposes files or member identities to guest users via these settings.',
        remediation: 'Keep guest file access and member visibility disabled as sites are updated.',
      });
    }

    return { findings };
  }
}
