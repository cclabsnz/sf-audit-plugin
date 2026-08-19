import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AdminUserRecord {
  Id: string;
  ProfileId: string;
  Username: string;
  Profile: { Name: string };
}

interface IpRangeRecord {
  ProfileId: string;
  StartAddress: string;
  EndAddress: string;
}

// Salesforce ConnectedApp ipRelaxation enum values (from Metadata API ConnectedAppIpRelaxation):
//   'WhiteList'  → enforce IP whitelist (secure)
//   'Relax'      → relax IP restrictions for connected apps (MEDIUM risk)
//   'All'        → bypass IP restrictions entirely (HIGH risk)
interface ConnectedAppRecord {
  Id: string;
  Name: string;
  Metadata: {
    oauthConfig?: {
      ipRelaxation?: string;
    };
  } | null;
}

// SBS-AUTH-003: detect ranges covering the full public internet or overly broad blocks.
// Anything larger than a /16 (65 536 hosts) is flagged; 0.0.0.0 start is always flagged.
function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] ?? 0) * 16_777_216) +
         ((parts[1] ?? 0) * 65_536) +
         ((parts[2] ?? 0) * 256) +
         (parts[3] ?? 0);
}

function rangeHostCount(start: string, end: string): number {
  return ipToNumber(end) - ipToNumber(start) + 1;
}

const BROAD_THRESHOLD = 65_536; // /16

export class IpRestrictionsCheck implements SecurityCheck {
  readonly id = 'ip-restrictions';
  readonly name = 'Login IP Restrictions';
  readonly category = 'Identity & Access';
  readonly description = 'Checks admin profiles for missing IP range restrictions and connected apps with relaxed IP policies';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // 1. Admin users (Modify All Data via profile)
    const adminUsers = await ctx.soql.queryAll<AdminUserRecord>(
      `SELECT Id, ProfileId, Profile.Name, Username FROM User
       WHERE IsActive = true AND Profile.PermissionsModifyAllData = true`
    );

    // 2. Profile IP ranges — try SOQL first, fallback to Tooling
    // "Unreadable" and "none configured" are different facts and must not be conflated: an
    // empty result would make every admin look unrestricted, asserting a finding the data
    // cannot support.
    let ipRanges: IpRangeRecord[] = [];
    let rangesUnavailable = false;
    try {
      ipRanges = await ctx.soql.queryAll<IpRangeRecord>(
        'SELECT ProfileId, StartAddress, EndAddress FROM ProfileLoginIpRange'
      );
    } catch {
      try {
        ipRanges = await ctx.tooling.query<IpRangeRecord>(
          'SELECT ProfileId, StartAddress, EndAddress FROM ProfileLoginIpRange'
        );
      } catch {
        rangesUnavailable = true;
      }
    }

    // 3. Connected apps — single Tooling SOQL with Metadata field (same pattern as
    // SELECT Body FROM ApexClass). Replaces the previous N+1 getRecord loop.
    // Salesforce ConnectedApp.Metadata.oauthConfig.ipRelaxation enum:
    //   'All'      → bypass IP restrictions (every IP allowed)
    //   'Relax'    → relax restrictions for this app's users
    //   'WhiteList'→ enforce the org-level IP whitelist (secure)
    const ipBypassingApps: Array<{ name: string; id: string }> = [];
    const ipRelaxingApps: Array<{ name: string; id: string }> = [];
    let appsUnavailable = false;
    try {
      const connectedApps = await ctx.tooling.query<ConnectedAppRecord>(
        'SELECT Id, Name, Metadata FROM ConnectedApplication'
      );
      for (const app of connectedApps) {
        const relaxation = app.Metadata?.oauthConfig?.ipRelaxation;
        if (relaxation === 'All') {
          ipBypassingApps.push({ name: app.Name, id: app.Id });
        } else if (relaxation === 'Relax') {
          ipRelaxingApps.push({ name: app.Name, id: app.Id });
        }
      }
    } catch {
      // Recorded so the result cannot be read as "no relaxed apps".
      appsUnavailable = true;
    }

    // Determine which profile IDs have at least one IP range
    const profilesWithRanges = new Set<string>(ipRanges.map((r) => r.ProfileId));

    // Admin users whose profile has no IP ranges
    const unrestrictedAdmins = adminUsers.filter(
      (u) => !profilesWithRanges.has(u.ProfileId)
    );

    if (rangesUnavailable && adminUsers.length > 0) {
      findings.push({
        id: 'ip-restrictions-ranges-unavailable',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `Login IP ranges could not be read; ${adminUsers.length} admin profile(s) were not evaluated`,
        detail:
          'ProfileLoginIpRange was not queryable via SOQL or the Tooling API, so whether these admin profiles restrict login by IP is unknown. It is not reported as unrestricted, because the data does not support that conclusion.',
        remediation:
          'Grant the audit user access to ProfileLoginIpRange and re-run, or review Login IP Ranges manually in Setup → Profiles.',
        affectedItems: adminUsers.map((u) => ({
          label: u.Username,
          url: `${baseUrl}/${u.Id}`,
          note: `Profile: ${u.Profile.Name}: IP range configuration unknown`,
        })),
      });
    }

    if (!rangesUnavailable && unrestrictedAdmins.length > 0) {
      findings.push({
        id: 'admin-no-ip-restrictions',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unrestrictedAdmins.length} admin user(s) have profiles without login IP restrictions`,
        affectedItems: unrestrictedAdmins.map((u) => ({
          label: u.Username,
          url: `${baseUrl}/${u.Id}`,
          note: `Profile: ${u.Profile.Name}: add IP ranges in Setup → Profiles → Login IP Ranges`,
        })),
        detail:
          'Administrator accounts without IP login restrictions can be accessed from any network, increasing exposure to credential-stuffing attacks.',
        remediation:
          'Add IP login ranges to all admin profiles in Setup → Profiles → Login IP Ranges, or enable MFA as a compensating control.',
      });
    }

    if (appsUnavailable) {
      findings.push({
        id: 'ip-restrictions-apps-unavailable',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Connected app IP relaxation settings could not be read',
        detail:
          'The ConnectedApplication Metadata field was not accessible, so whether any connected app bypasses or relaxes login IP enforcement is unknown.',
        remediation:
          'Grant the audit user access to the Tooling API ConnectedApplication Metadata field and re-run, or review IP Relaxation per app in Setup → Connected Apps.',
      });
    }

    if (ipBypassingApps.length > 0) {
      findings.push({
        id: 'connected-apps-bypass-ip',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${ipBypassingApps.length} connected app(s) completely bypass login IP enforcement`,
        affectedItems: ipBypassingApps.map((app) => ({
          label: app.name,
          url: `${baseUrl}/lightning/setup/ConnectedApplication/page`,
          note: 'IP Relaxation = All: change to "Enforce IP Restrictions" or "Relax IP Restrictions" to reinstate controls',
        })),
        detail:
          `Connected apps configured with IP Relaxation set to "All" allow API access from any IP address for any user, completely overriding profile-level IP restrictions. An attacker with a stolen OAuth token or credential can authenticate from anywhere regardless of org-level IP policies.`,
        remediation:
          'Set IP Relaxation to "Enforce IP Restrictions" (WhiteList) for all connected apps unless there is a documented, audited business requirement for remote access. Review each app and confirm the relaxation setting is intentional.',
      });
    }

    if (ipRelaxingApps.length > 0) {
      findings.push({
        id: 'connected-apps-relax-ip',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${ipRelaxingApps.length} connected app(s) relax login IP enforcement for their users`,
        affectedItems: ipRelaxingApps.map((app) => ({
          label: app.name,
          url: `${baseUrl}/lightning/setup/ConnectedApplication/page`,
          note: 'IP Relaxation = Relax: confirm documented justification exists',
        })),
        detail:
          `Connected apps configured with IP Relaxation set to "Relax" allow the app's users to access the org from outside the IP ranges defined on their profile when using this app. This weakens the IP restriction control for API access.`,
        remediation:
          'Set IP Relaxation to "Enforce IP Restrictions" unless the integration genuinely requires access from IP addresses outside the corporate network. Document any justified relaxations in the system of record.',
      });
    }

    // SBS-AUTH-003: flag overly broad IP ranges on any profile that has ranges configured.
    interface BroadRange {
      profileId: string;
      profileName: string;
      start: string;
      end: string;
      hostCount: number;
    }
    const broadRanges: BroadRange[] = [];

    // Build a map of profileId → profile name from admin users (best effort)
    const profileNameMap = new Map<string, string>(
      adminUsers.map((u) => [u.ProfileId, u.Profile.Name])
    );

    for (const range of ipRanges) {
      const count = rangeHostCount(range.StartAddress, range.EndAddress);
      if (count >= BROAD_THRESHOLD || range.StartAddress === '0.0.0.0') {
        broadRanges.push({
          profileId: range.ProfileId,
          profileName: profileNameMap.get(range.ProfileId) ?? range.ProfileId,
          start: range.StartAddress,
          end: range.EndAddress,
          hostCount: count,
        });
      }
    }

    if (broadRanges.length > 0) {
      findings.push({
        id: 'broad-ip-ranges',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${broadRanges.length} login IP range(s) are overly broad (>${BROAD_THRESHOLD.toLocaleString()} hosts or start at 0.0.0.0)`,
        detail:
          'SBS-AUTH-003 requires that profile IP ranges do not cover the full public internet or excessively large blocks. Broad ranges effectively disable IP-based login controls.',
        remediation:
          'Replace overly broad IP ranges with your specific corporate network CIDR blocks. Remove 0.0.0.0 start addresses entirely.',
        affectedItems: broadRanges.map((r) => ({
          label: r.profileName,
          url: `${baseUrl}/lightning/setup/Profiles/home`,
          note: `${r.start} – ${r.end} (${r.hostCount.toLocaleString()} hosts)`,
        })),
      });
    }

    if (
      !rangesUnavailable &&
      !appsUnavailable &&
      unrestrictedAdmins.length === 0 &&
      ipBypassingApps.length === 0 &&
      ipRelaxingApps.length === 0 &&
      broadRanges.length === 0
    ) {
      findings.push({
        id: 'ip-restrictions-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Login IP restrictions appear appropriately configured',
        detail:
          'All checked admin profiles have login IP ranges configured, no connected apps bypass or relax IP enforcement, and no overly broad ranges were found.',
        remediation:
          'Periodically review IP restriction configuration as new admins and connected apps are added.',
      });
    }

    return { findings };
  }
}
