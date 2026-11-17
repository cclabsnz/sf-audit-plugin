import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkAccessRecord {
  StartAddress: string;
  EndAddress: string;
  Description: string | null;
}

// Trusted IP ranges live in the Metadata API (SecuritySettings.networkAccess.ipRanges). The
// standard API does not serve NetworkAccess, and the Tooling object carries only Id and DurableId.
interface SecuritySettingsMetadata {
  networkAccess?: {
    ipRanges?: Array<{ start?: string; end?: string; description?: string }> | { start?: string; end?: string; description?: string };
  } | null;
}

// What a trusted IP range does: a login from inside the range skips Device Activation, the
// identity verification challenge Salesforce shows on an unrecognised browser or device. It does
// not exempt a user from multi-factor authentication, which is a permanent part of the login
// experience and is not bypassed from a trusted network; a login that uses MFA or strong SSO
// authentication skips device activation anyway. Once trusted ranges total more than 16,777,216
// IPv4 addresses (10.0.0.0/8 not counted), users can be challenged even from a trusted address.
// Sources:
//   https://help.salesforce.com/s/articleView?id=xcloud.device_activation_orgs.htm&type=5
//   https://help.salesforce.com/s/articleView?id=005237070&type=1 (device activation and trusted IP ranges)
const DEVICE_ACTIVATION_LIMIT = 16_777_216;
const TEN_START = 0x0a000000;
const TEN_END = 0x0affffff;

/** Addresses in [start, end] outside 10.0.0.0/8, which Salesforce leaves out of the trusted-range limit. */
function countedSize(start: string, end: string): number {
  const s = ipToInt(start);
  const e = ipToInt(end);
  const overlap = Math.max(0, Math.min(e, TEN_END) - Math.max(s, TEN_START) + 1);
  return e - s + 1 - overlap;
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
  readonly description = 'Identifies trusted IP ranges, which skip the identity verification challenge, including overly broad ranges';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SecurityNetworkAccess/home`;

    let settings: SecuritySettingsMetadata | null = null;
    let error = 'this run has no Metadata API client';
    if (ctx.metadata) {
      try {
        settings = await ctx.metadata.read<SecuritySettingsMetadata>('SecuritySettings', 'Security');
        if (!settings) error = 'the Security settings were not returned';
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
      }
    }
    if (!settings) {
      findings.push({
        id: 'trusted-ip-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Trusted IP ranges could not be retrieved',
        detail: `Trusted IP ranges are read from the Security settings in the Metadata API, and could not be: ${error}.`,
        remediation:
          'Review trusted IP ranges manually in Setup → Security → Network Access. Ensure the audit user has "View Setup and Configuration" permission.',
        affectedItems: [{ label: 'Network Access Setup', url: setupUrl }],
      });
      return { findings };
    }

    // The Metadata API returns a single range as an object, several as an array.
    const raw = settings.networkAccess?.ipRanges;
    const ranges: NetworkAccessRecord[] = (raw === undefined ? [] : Array.isArray(raw) ? raw : [raw])
      .filter((r) => r.start && r.end)
      .map((r) => ({ StartAddress: r.start!, EndAddress: r.end!, Description: r.description ?? null }));

    if (ranges.length === 0) {
      findings.push({
        id: 'trusted-ip-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No trusted IP ranges configured: identity verification applies to all login locations',
        detail:
          'No NetworkAccess (trusted IP range) records are configured. Every login from an unrecognised browser or device gets the identity verification (Device Activation) challenge, whatever its network location.',
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

    let counted = 0;
    for (const r of ranges) {
      try {
        counted += countedSize(r.StartAddress, r.EndAddress);
      } catch {
        // unparseable range: leave it out of the total
      }
    }
    const overLimit = counted > DEVICE_ACTIVATION_LIMIT;

    if (broadRanges.length > 0) {
      findings.push({
        id: 'trusted-ip-broad-ranges',
        category: this.category,
        riskLevel: overLimit ? 'LOW' : 'MEDIUM',
        title: `${broadRanges.length} trusted IP range(s) cover more than 65,536 hosts (broader than /16)`,
        detail: overLimit
          ? `The trusted ranges total ${counted.toLocaleString()} addresses outside 10.0.0.0/8, more than the 16,777,216 Salesforce allows before it challenges logins from trusted addresses anyway. So device activation still applies, and these ranges mostly add confusion about what is trusted.`
          : 'A login from a trusted IP range skips the identity verification (Device Activation) challenge that Salesforce shows on an unrecognised browser or device. It does not skip multi-factor authentication, and a login that uses MFA or strong SSO authentication skips device activation anyway. So for logins that do not use MFA or strong SSO, anyone with stolen credentials and a foothold on any host in a range broader than /16 signs in from a new device without being asked to verify it.',
        remediation:
          'Narrow each trusted IP range to the minimum required set of specific host addresses or subnets. Remove overly broad ranges. If broad ranges are required, document the business justification and ensure compensating controls (VPN enforcement, NAC, EDR) are in place.',
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
      riskLevel: 'LOW',
      title: `${ranges.length} trusted IP range(s) configured: identity verification is skipped for logins from these addresses`,
      detail:
        'Logins from a listed IP address skip the identity verification (Device Activation) challenge for unrecognised browsers and devices. They are not exempt from multi-factor authentication. Each range should have a documented justification and be reviewed regularly, because ranges accumulate and widen the set of networks where a new device is trusted without a challenge.',
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
