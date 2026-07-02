import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser {
  Id: string;
  Username: string;
}
interface PsaRec {
  AssigneeId: string;
  PermissionSet: {
    Label: string;
    PermissionsApiEnabled: boolean;
    PermissionsBulkApiHardDelete: boolean;
  } | null;
}

/**
 * Flags guest (unauthenticated) users whose profile/permission-sets grant API or
 * Bulk API access. The other guest checks cover the UI-API/GraphQL vector; this
 * covers the *programmatic* one: a guest with "API Enabled" can drive the REST/SOAP/
 * Bulk API directly, turning any readable object into a scriptable bulk pull, and
 * "Bulk API Hard Delete" additionally lets an anonymous caller permanently destroy
 * records (bypassing the recycle bin).
 */
export class GuestApiAccessCheck implements SecurityCheck {
  readonly id = 'guest-api-access';
  readonly name = 'Guest API & Bulk Access';
  readonly category = 'Access Control';
  readonly description =
    'Flags guest users granted API Enabled or Bulk API Hard Delete — programmatic bulk read/delete access for unauthenticated visitors';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>("SELECT Id, Username FROM User WHERE UserType = 'Guest' AND IsActive = true");
    } catch {
      findings.push(this.inconclusive('Guest users could not be queried'));
      return { findings };
    }
    if (guests.length === 0) {
      findings.push({
        id: 'guest-api-access-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users',
        detail: 'There are no active guest users, so there is no guest API surface.',
        remediation: 'If a public site is added later, keep API Enabled and Bulk API permissions off the guest profile.',
      });
      return { findings };
    }

    const inIds = guests.map((g) => `'${g.Id}'`).join(', ');
    let psa: PsaRec[];
    try {
      psa = await ctx.soql.queryAll<PsaRec>(
        `SELECT AssigneeId, PermissionSet.Label, PermissionSet.PermissionsApiEnabled, PermissionSet.PermissionsBulkApiHardDelete
         FROM PermissionSetAssignment WHERE AssigneeId IN (${inIds})`,
      );
    } catch {
      findings.push(this.inconclusive('Guest permission sets could not be queried'));
      return { findings };
    }

    const guestById = new Map(guests.map((g) => [g.Id, g]));
    const apiGuests = new Map<string, Set<string>>(); // guestId -> permset labels granting API
    const hardDeleteGuests = new Map<string, Set<string>>();
    for (const a of psa) {
      if (!a.PermissionSet) continue;
      if (a.PermissionSet.PermissionsApiEnabled) {
        (apiGuests.get(a.AssigneeId) ?? apiGuests.set(a.AssigneeId, new Set()).get(a.AssigneeId)!).add(a.PermissionSet.Label);
      }
      if (a.PermissionSet.PermissionsBulkApiHardDelete) {
        (hardDeleteGuests.get(a.AssigneeId) ?? hardDeleteGuests.set(a.AssigneeId, new Set()).get(a.AssigneeId)!).add(a.PermissionSet.Label);
      }
    }

    if (apiGuests.size > 0) {
      findings.push({
        id: 'guest-api-access-enabled',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${apiGuests.size} guest user(s) have API access enabled`,
        detail:
          '"API Enabled" on a guest user lets an unauthenticated caller drive the REST/SOAP/Bulk API directly, not just the site UI. Every object the guest can read becomes a scriptable bulk-extraction target, and this bypasses UI-only assumptions about what guests can reach.',
        remediation:
          'Remove "API Enabled" from the guest profile and any permission set assigned to the guest user. Guests should interact only through the site\'s Apex/LWC, never the raw API.',
        affectedItems: [...apiGuests.entries()].slice(0, 30).map(([id, sets]) => ({
          label: `${guestById.get(id)?.Username ?? id} — via ${[...sets].join(', ')}`,
          url: `${baseUrl}/lightning/setup/PermSets/home`,
        })),
      });
    }

    if (hardDeleteGuests.size > 0) {
      findings.push({
        id: 'guest-api-hard-delete',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${hardDeleteGuests.size} guest user(s) have Bulk API Hard Delete`,
        detail:
          '"Bulk API Hard Delete" lets the holder permanently delete records, skipping the recycle bin. On a guest user this hands an unauthenticated visitor an irreversible destructive capability.',
        remediation: 'Immediately remove "Bulk API Hard Delete" from all guest profiles/permission sets.',
        affectedItems: [...hardDeleteGuests.entries()].slice(0, 30).map(([id, sets]) => ({
          label: `${guestById.get(id)?.Username ?? id} — via ${[...sets].join(', ')}`,
          url: `${baseUrl}/lightning/setup/PermSets/home`,
        })),
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'guest-api-access-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${guests.length} guest user(s); no API or Bulk API access`,
        detail: 'No active guest user has "API Enabled" or "Bulk API Hard Delete", so guests cannot drive the raw API.',
        remediation: 'Keep API and Bulk permissions off guest profiles as sites change.',
      });
    }

    return { findings };
  }

  private inconclusive(what: string): Finding {
    return {
      id: 'guest-api-access-inconclusive',
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather the data needed to evaluate guest API access.',
      remediation: 'Grant the audit user View Setup and Configuration and re-run.',
    };
  }
}
