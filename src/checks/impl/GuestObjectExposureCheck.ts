import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser {
  Id: string;
  ProfileId: string;
  Username: string;
}
interface PermSetAssignment {
  AssigneeId: string;
  PermissionSetId: string;
}
interface ObjectPermission {
  ParentId: string;
  SobjectType: string;
  PermissionsRead: boolean;
  PermissionsCreate: boolean;
  PermissionsEdit: boolean;
  PermissionsDelete: boolean;
}
interface EntityDef {
  QualifiedApiName: string;
  ExternalSharingModel: string | null;
}

// External sharing models that expose ALL records of an object to external (guest) users.
const PUBLIC_OWD = new Set(['Read', 'ReadWrite', 'ReadSelect']);

/**
 * Detects every object an unauthenticated guest can READ IN BULK. Unlike
 * GuestUserAccessCheck (a fixed list of standard objects + sharing rules), this
 * auto-discovers ALL objects the guest profile/permission-sets can read, then
 * decides whether records are actually reachable:
 *   - public external OWD (Read/ReadWrite) => every record is readable, OR
 *   - Private OWD but the guest OWNS records (public-form submissions) => those
 *     records are still readable, because an owner can always read its own records.
 * Any readable object is reachable unauthenticated through the Experience Cloud
 * UI API (GraphQL) via the Aura endpoint, so this is a bulk-exfiltration surface.
 */
export class GuestObjectExposureCheck implements SecurityCheck {
  readonly id = 'guest-object-exposure';
  readonly name = 'Guest Object Exposure (Bulk Read via UI API)';
  readonly category = 'Access Control';
  readonly description =
    'Auto-discovers every object an unauthenticated guest can read in bulk via the UI API (GraphQL), including records exposed by guest ownership despite a Private org-wide default';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>(
        "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true",
      );
    } catch {
      findings.push(this.inconclusive('guest-object-exposure-inaccessible', 'Guest users could not be queried'));
      return { findings };
    }

    if (guests.length === 0) {
      findings.push({
        id: 'guest-object-exposure-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users',
        detail: 'There are no active guest users, so no unauthenticated UI-API bulk-read surface exists.',
        remediation: 'If an Experience Cloud or Sites site is added later, re-run this check.',
      });
      return { findings };
    }

    const guestIds = guests.map((g) => g.Id);
    const inIds = guestIds.map((i) => `'${i}'`).join(', ');

    // Permission sets (profile-owned + assigned) that grant the guests their access.
    let permSetIds: string[];
    try {
      const psa = await ctx.soql.queryAll<PermSetAssignment>(
        `SELECT AssigneeId, PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId IN (${inIds})`,
      );
      permSetIds = [...new Set(psa.map((p) => p.PermissionSetId))];
    } catch {
      findings.push(this.inconclusive('guest-object-exposure-perms-inaccessible', 'Guest permission sets could not be queried'));
      return { findings };
    }
    if (permSetIds.length === 0) {
      findings.push(this.ok(guests.length, 0));
      return { findings };
    }

    // Every object the guest can read — auto-discovered, not a fixed list.
    const psIn = permSetIds.map((i) => `'${i}'`).join(', ');
    let perms: ObjectPermission[];
    try {
      perms = await ctx.soql.queryAll<ObjectPermission>(
        `SELECT ParentId, SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete
         FROM ObjectPermissions WHERE ParentId IN (${psIn}) AND PermissionsRead = true`,
      );
    } catch {
      findings.push(this.inconclusive('guest-object-exposure-objperms-inaccessible', 'Guest object permissions could not be queried'));
      return { findings };
    }
    const writable = new Set(perms.filter((p) => p.PermissionsCreate || p.PermissionsEdit || p.PermissionsDelete).map((p) => p.SobjectType));
    const readable = [...new Set(perms.map((p) => p.SobjectType))];
    if (readable.length === 0) {
      findings.push(this.ok(guests.length, 0));
      return { findings };
    }

    // External OWD for each readable object.
    const owd = new Map<string, string>();
    try {
      const objList = readable.map((o) => `'${o}'`).join(', ');
      const defs = await ctx.soql.queryAll<EntityDef>(
        `SELECT QualifiedApiName, ExternalSharingModel FROM EntityDefinition WHERE QualifiedApiName IN (${objList})`,
      );
      for (const d of defs) owd.set(d.QualifiedApiName, d.ExternalSharingModel ?? 'Unknown');
    } catch {
      // Proceed without OWD: objects fall through to the ownership check below.
    }

    const publicExposed: Array<{ obj: string; owd: string; write: boolean }> = [];
    const ownedExposed: Array<{ obj: string; count: number; write: boolean }> = [];
    for (const obj of readable) {
      const model = owd.get(obj) ?? 'Unknown';
      if (PUBLIC_OWD.has(model)) {
        publicExposed.push({ obj, owd: model, write: writable.has(obj) });
        continue;
      }
      // Private or Unknown OWD: records are still exposed if the guest OWNS them.
      try {
        const r = await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${obj} WHERE OwnerId IN (${inIds})`);
        if (r.totalSize > 0) ownedExposed.push({ obj, count: r.totalSize, write: writable.has(obj) });
      } catch {
        // Object has no OwnerId / does not support COUNT — not an ownership-bypass surface.
      }
    }

    const uiApiNote =
      'Reachable unauthenticated via the Experience Cloud UI API (GraphQL) through aura://RecordUiController/ACTION$executeGraphQL on /s/sfsites/aura (aura.token=null).';

    if (publicExposed.length > 0) {
      findings.push({
        id: 'guest-object-exposure-public-owd',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${publicExposed.length} object(s) fully readable by unauthenticated guests (public external OWD)`,
        detail:
          'These objects have an external org-wide default of Read or ReadWrite and are readable by the guest profile. Every record is therefore exposed to any unauthenticated visitor, who can enumerate counts and page through records in bulk. ' +
          uiApiNote,
        remediation:
          'Set external OWD to Private for these objects, and remove Read from the guest profile/permission sets unless a specific public dataset is intended. Then verify no guest-accessible Apex returns the data.',
        affectedItems: publicExposed.map((e) => ({
          label: `${e.obj} (external OWD: ${e.owd}${e.write ? ', guest WRITE too' : ''})`,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: 'All records readable unauthenticated via UI API',
        })),
      });
    }
    if (ownedExposed.length > 0) {
      findings.push({
        id: 'guest-object-exposure-guest-owned',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${ownedExposed.length} object(s) expose guest-owned records despite a Private OWD`,
        detail:
          'These objects have a Private external OWD, but the guest user OWNS records in them (typically public-form submissions created as the guest user). An owner can always read its own records, so Private OWD does not protect them. All guest-owned records are readable unauthenticated in bulk. ' +
          uiApiNote,
        remediation:
          'Reparent guest-created records to a default or integration owner (enable "Assign records created by guest users to the default owner" and "Secure guest user record access"), and remove Read on these objects from the guest profile.',
        affectedItems: ownedExposed.map((e) => ({
          label: `${e.obj}: ${e.count} guest-owned record(s)${e.write ? ' (guest WRITE too)' : ''}`,
          url: `${baseUrl}/${e.obj}`,
          note: 'Readable unauthenticated via UI API despite Private OWD',
        })),
      });
    }
    if (publicExposed.length === 0 && ownedExposed.length === 0) {
      findings.push(this.ok(guests.length, readable.length));
    }
    return { findings };
  }

  private ok(guestCount: number, readableCount: number): Finding {
    return {
      id: 'guest-object-exposure-ok',
      category: this.category,
      riskLevel: 'LOW',
      passed: true,
      title: `${guestCount} active guest user(s); no objects bulk-exposed`,
      detail:
        readableCount === 0
          ? 'Guest profiles grant Read on no business objects, so there is no UI-API bulk-read surface.'
          : `Guest profiles can read ${readableCount} object(s), but all have a Private external OWD with no guest-owned records, so no records are bulk-readable.`,
      remediation: 'Continue to review guest object permissions and record ownership as forms and sites change.',
    };
  }

  private inconclusive(id: string, what: string): Finding {
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather the data needed to evaluate guest object exposure.',
      remediation: 'Grant the audit user View Setup and Configuration plus read on the relevant objects, then re-run.',
    };
  }
}
