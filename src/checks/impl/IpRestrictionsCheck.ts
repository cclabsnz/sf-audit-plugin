import type { AuditContext } from '../../context/AuditContext.js';
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

interface ConnectedAppBasicRecord {
  Id: string;
  Name: string;
}

interface ConnectedAppDetailRecord {
  Id: string;
  Name: string;
  Metadata?: { ipRelaxation?: string };
}

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
    let ipRanges: IpRangeRecord[] = [];
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
        // No IP ranges configured or not accessible — treat as empty
        ipRanges = [];
      }
    }

    // 3. Connected apps with IP relaxation
    let connectedApps: ConnectedAppBasicRecord[] = [];
    try {
      connectedApps = await ctx.tooling.query<ConnectedAppBasicRecord>(
        'SELECT Id, Name FROM ConnectedApplication'
      );
    } catch {
      connectedApps = [];
    }

    const ipBypassingApps: Array<{ name: string; id: string }> = [];
    for (const app of connectedApps) {
      try {
        const detail = await ctx.tooling.getRecord<ConnectedAppDetailRecord>(
          'ConnectedApplication',
          app.Id
        );
        const relaxation = detail.Metadata?.ipRelaxation;
        if (relaxation === 'BYPASS' || relaxation === 'RELAX_IP') {
          ipBypassingApps.push({ name: app.Name, id: app.Id });
        }
      } catch {
        // Skip apps whose detail record cannot be fetched
      }
    }

    // Determine which profile IDs have at least one IP range
    const profilesWithRanges = new Set<string>(ipRanges.map((r) => r.ProfileId));

    // Admin users whose profile has no IP ranges
    const unrestrictedAdmins = adminUsers.filter(
      (u) => !profilesWithRanges.has(u.ProfileId)
    );

    if (unrestrictedAdmins.length > 0) {
      findings.push({
        id: 'admin-no-ip-restrictions',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unrestrictedAdmins.length} admin user(s) have profiles without login IP restrictions`,
        affectedItems: unrestrictedAdmins.map((u) => ({
          label: u.Username,
          url: `${baseUrl}/${u.Id}`,
          note: `Profile: ${u.Profile.Name} — add IP ranges in Setup → Profiles → Login IP Ranges`,
        })),
        detail:
          'Administrator accounts without IP login restrictions can be accessed from any network, increasing exposure to credential-stuffing attacks.',
        remediation:
          'Add IP login ranges to all admin profiles in Setup → Profiles → Login IP Ranges, or enable MFA as a compensating control.',
      });
    }

    if (ipBypassingApps.length > 0) {
      findings.push({
        id: 'connected-apps-bypass-ip',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${ipBypassingApps.length} connected app(s) bypass login IP enforcement`,
        affectedItems: ipBypassingApps.map((app) => ({
          label: app.name,
          url: `${baseUrl}/lightning/setup/ConnectedApplication/page`,
          note: 'Set IP Relaxation to "Enforce IP restrictions" unless remote access is required',
        })),
        detail:
          "Connected apps configured to relax IP restrictions allow API access from any IP address, even when the user's profile has IP restrictions.",
        remediation:
          'Set IP Relaxation to "Enforce IP restrictions" for connected apps unless there is a documented business requirement for remote access.',
      });
    }

    if (unrestrictedAdmins.length === 0 && ipBypassingApps.length === 0) {
      findings.push({
        id: 'ip-restrictions-ok',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Login IP restrictions appear appropriately configured',
        detail:
          'All checked admin profiles have login IP ranges configured and no connected apps bypass IP enforcement.',
        remediation:
          'Periodically review IP restriction configuration as new admins and connected apps are added.',
      });
    }

    return { findings };
  }
}
