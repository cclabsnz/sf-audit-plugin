import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkAccessRecord {
  Id: string;
  StartAddress: string;
  EndAddress: string;
  Description: string | null;
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}

function rangeSize(start: string, end: string): number {
  return ipToInt(end) - ipToInt(start) + 1;
}

export class TrustedIPRangesCheck implements SecurityCheck {
  readonly id = 'trusted-ip-ranges';
  readonly name = 'Trusted IP Ranges';
  readonly category = 'Authentication';
  readonly description = 'Identifies trusted IP ranges that completely bypass MFA, including overly broad ranges';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SecurityNetworkAccess/home`;

    let ranges: NetworkAccessRecord[] = [];
    try {
      const result = await ctx.soql.query<NetworkAccessRecord>(
        `SELECT Id, StartAddress, EndAddress, Description
         FROM NetworkAccess
         ORDER BY StartAddress
         LIMIT 200`
      );
      ranges = result.records;
    } catch {
      findings.push({
        id: 'trusted-ip-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Trusted IP ranges could not be retrieved',
        detail:
          'The NetworkAccess object was not accessible. This may indicate insufficient permissions to query network access settings.',
        remediation:
          'Review trusted IP ranges manually in Setup → Security → Network Access. Ensure the audit user has "View Setup and Configuration" permission.',
        affectedItems: [{ label: 'Network Access Setup', url: setupUrl }],
      });
      return { findings };
    }

    if (ranges.length === 0) {
      findings.push({
        id: 'trusted-ip-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No trusted IP ranges configured: MFA applies to all login locations',
        detail:
          'No NetworkAccess (trusted IP range) records are configured. All users are subject to MFA and login challenge enforcement regardless of their network location.',
        remediation:
          'Continue to avoid configuring trusted IP ranges unless there is a documented, justified business requirement with compensating controls.',
      });
      return { findings };
    }

    const broadRanges = ranges.filter((r) => {
      try {
        return rangeSize(r.StartAddress, r.EndAddress) > 65_536;
      } catch {
        return false;
      }
    });

    if (broadRanges.length > 0) {
      findings.push({
        id: 'trusted-ip-broad-ranges',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${broadRanges.length} trusted IP range(s) cover more than 65,536 hosts (broader than /16)`,
        detail:
          'Trusted IP ranges completely bypass Salesforce MFA. Any user logging in from a trusted IP is not challenged for a second factor. Ranges broader than /16 cover entire enterprise network blocks or ISP ranges, creating an extremely large MFA bypass surface. If an attacker or insider gains access to any host within that range, they can log in without MFA.',
        remediation:
          'Narrow each trusted IP range to the minimum required set of specific host addresses or subnets. Remove overly broad ranges immediately. If broad ranges are required, document the business justification and ensure compensating controls (network-level MFA, VPN enforcement, EDR) are in place.',
        affectedItems: broadRanges.map((r) => {
          let size: string;
          try {
            size = rangeSize(r.StartAddress, r.EndAddress).toLocaleString();
          } catch {
            size = 'unknown';
          }
          return {
            label: `${r.StartAddress}–${r.EndAddress}`,
            url: setupUrl,
            note: `${r.Description ?? 'no description'}, ${size} hosts`,
          };
        }),
      });
    }

    findings.push({
      id: 'trusted-ip-exists',
      category: this.category,
      riskLevel: 'MEDIUM',
      title: `${ranges.length} trusted IP range(s) configured: MFA is bypassed for logins from these addresses`,
      detail:
        'Trusted IP ranges in Salesforce completely bypass MFA enforcement. Any user authenticating from a listed IP address is not required to provide a second factor. Each range must have documented justification and be reviewed regularly. Without this review, ranges can accumulate and silently expand the MFA bypass surface over time.',
      remediation:
        'Review each trusted IP range and confirm it has a documented business justification. Remove any ranges that are no longer required or cannot be justified. Ensure compensating network controls (VPN with MFA, NAC, EDR) protect the trusted network segments.',
      affectedItems: ranges.map((r) => {
        let size: string;
        try {
          size = rangeSize(r.StartAddress, r.EndAddress).toLocaleString();
        } catch {
          size = 'unknown';
        }
        return {
          label: `${r.StartAddress}–${r.EndAddress}`,
          url: setupUrl,
          note: `${r.Description ?? 'no description'}, ${size} hosts`,
        };
      }),
    });

    return { findings };
  }
}
