import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { guestPrincipals, guestReadsSample, guestShareCount } from '../support/guestShares.js';

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

// Objects whose guest shares GuestUserAccessCheck already reports as guest-user-sharing-exposure.
const REPORTED_BY_GUEST_ACCESS = new Set(['Account', 'Case', 'Contact', 'Opportunity']);

// Public external sharing models. Since Winter '21 secure guest record access is always enforced,
// so these open records to logged-in external users but not to guests: record sharing gives a guest
// a record only through a guest sharing rule or ownership. (Guest-callable Apex or Flow running
// without sharing bypasses sharing; their own checks report that.) A public external OWD plus guest Read is therefore
// a lead to confirm with UserRecordAccess, not an exposure on its own.
const PUBLIC_OWD = new Set(['Read', 'ReadWrite', 'ReadSelect']);

// uiApi:      true  = UI API models the object (reachable via executeGraphQL),
//             false = object-info returned not-modeled (NOT reachable via that vector),
//             null  = could not probe (assume reachable, the conservative default).
// confirmed:  true     = UserRecordAccess confirms a guest user can read a sampled record,
//             false    = no guest user can read any sampled record (up to 200),
//             null     = no sample record to test (config object / empty table),
//             'failed' = the sample or UserRecordAccess query failed.
interface ExposedObject {
  obj: string;
  owd?: string;
  count?: number;
  write: boolean;
  kind: 'public' | 'owned' | 'shared';
  uiApi: boolean | null;
  confirmed: boolean | null | 'failed';
}

/**
 * Detects every object an unauthenticated guest can READ IN BULK. Unlike
 * GuestUserAccessCheck (a fixed list of standard objects + sharing rules), this
 * auto-discovers ALL objects the guest profile/permission-sets can read, then
 * decides whether records are actually reachable:
 *   - public external OWD (Read/ReadWrite) AND UserRecordAccess confirms the guest reads a
 *     live record (secure guest record access means the OWD alone grants guests nothing), OR
 *   - Private OWD but the guest OWNS records (public-form submissions) => those
 *     records are still readable, because an owner can always read its own records, OR
 *   - Private OWD but records are shared with guests (a guest user sharing rule, or a legacy
 *     manual, Apex or group share), read from the object's share table and, when it shows none or
 *     cannot be read, from UserRecordAccess on a sample.
 *
 * Sharing-model readability is necessary but not sufficient: the Experience Cloud
 * UI API (GraphQL) can only return objects it MODELS. Objects like Calendar,
 * AuthSession, or OauthToken can be readable in the sharing model yet fail the UI
 * API `object-info` endpoint, so they are NOT reachable through the guest GraphQL
 * vector. This check therefore probes `object-info` per exposed object and grades:
 *   - Tier 1 (CRITICAL): sharing-readable AND UI-API-modeled  => actually pullable.
 *   - Tier 2 (MEDIUM):   sharing-readable but NOT UI-API-modeled => defense-in-depth
 *     only (remove the grant, but it is not the bulk-exfiltration vector).
 * Where a live record exists, UserRecordAccess is queried as ground-truth read
 * confirmation and surfaced in the finding evidence.
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
    // Guests can hold only Read and Create object permissions since Winter '21.
    const writable = new Set(perms.filter((p) => p.PermissionsCreate).map((p) => p.SobjectType));
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

    const principals = await guestPrincipals(ctx, guestIds);
    const exposed: ExposedObject[] = [];
    for (const obj of readable) {
      const model = owd.get(obj) ?? 'Unknown';
      // GuestUserAccessCheck owns guest reads on these four (guest-user-sharing-exposure: share
      // rows, or UserRecordAccess when there are none), whatever their OWD, so they are not graded
      // twice. Guest-owned records on them are reported here, and only here.
      if (REPORTED_BY_GUEST_ACCESS.has(obj)) {
        try {
          const r = await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${obj} WHERE OwnerId IN (${inIds})`);
          if (r.totalSize > 0) exposed.push({ obj, count: r.totalSize, write: writable.has(obj), kind: 'owned', uiApi: null, confirmed: null });
        } catch {
          // No OwnerId: ownership cannot expose it.
        }
        continue;
      }
      if (PUBLIC_OWD.has(model)) {
        exposed.push({ obj, owd: model, write: writable.has(obj), kind: 'public', uiApi: null, confirmed: null });
        continue;
      }
      // Private or Unknown OWD: records are still exposed if the guest OWNS them.
      try {
        const r = await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${obj} WHERE OwnerId IN (${inIds})`);
        if (r.totalSize > 0) {
          exposed.push({ obj, count: r.totalSize, write: writable.has(obj), kind: 'owned', uiApi: null, confirmed: null });
          continue;
        }
      } catch {
        // Object has no OwnerId / does not support COUNT — not an ownership-bypass surface.
      }
      // Or if they are shared with guests: a guest sharing rule is what secure guest record access
      // leaves as the guest's way to a record it does not own, and legacy shares persist.
      const shared = await guestShareCount(ctx, obj, principals);
      if (shared !== null && shared > 0) {
        exposed.push({ obj, count: shared, write: writable.has(obj), kind: 'shared', uiApi: null, confirmed: true });
      } else if ((await guestReadsSample(ctx, obj, guestIds)) === true) {
        // No share row seen (no share table, a parent-controlled object, or a path the table does
        // not show), but the guest reads a sampled record.
        exposed.push({ obj, write: writable.has(obj), kind: 'shared', uiApi: null, confirmed: true });
      }
    }

    // Grade each sharing-readable object by ACTUAL UI-API reachability + ground-truth read.
    for (const e of exposed) {
      e.uiApi = await this.isUiApiModeled(ctx, e.obj);
      if (e.kind === 'shared') continue;
      // The external OWD does not reach guests, so on a public-OWD object a guest reads records the
      // same way as under a Private one: through shares. Those are graded as shared records.
      const shared = e.kind === 'public' ? await guestShareCount(ctx, e.obj, principals) : null;
      if (shared !== null && shared > 0) {
        Object.assign(e, { kind: 'shared', count: shared, confirmed: true });
        continue;
      }
      e.confirmed = await guestReadsSample(ctx, e.obj, guestIds);
      // An unconfirmed public-OWD object can still hold records the guest owns, which it always reads.
      if (e.kind === 'public' && e.confirmed !== true) {
        try {
          const r = await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${e.obj} WHERE OwnerId IN (${inIds})`);
          if (r.totalSize > 0) Object.assign(e, { kind: 'owned', count: r.totalSize });
        } catch {
          // No OwnerId: ownership cannot expose it.
        }
      }
    }
    // uiApi === false is the ONLY signal that de-escalates (object-info explicitly said
    // "not modeled"). true and null (couldn't probe) both stay in the reachable tier.
    const publicOwd = exposed.filter((e) => e.kind === 'public' && e.uiApi !== false);
    const reachablePublic = publicOwd.filter((e) => e.confirmed === true);
    const unconfirmedPublic = publicOwd.filter((e) => e.confirmed !== true);
    const reachableOwned = exposed.filter((e) => e.kind === 'owned' && e.uiApi !== false);
    const reachableShared = exposed.filter((e) => e.kind === 'shared' && e.uiApi !== false);
    const sharingOnly = exposed.filter((e) => e.uiApi === false);

    const uiApiNote =
      'Reachable unauthenticated via the Experience Cloud UI API (GraphQL) through aura://RecordUiController/ACTION$executeGraphQL on /s/sfsites/aura (aura.token=null).';

    if (reachablePublic.length > 0) {
      findings.push({
        id: 'guest-object-exposure-public-owd',
        category: this.category,
        // Graded like guest-object-exposure-guest-shared: the external OWD does not reach guests, so
        // these records reach them through sharing, which a site may intend.
        riskLevel: 'HIGH',
        title: `${reachablePublic.length} object(s) with records confirmed readable by unauthenticated guests`,
        detail:
          'The guest profile can read these objects, their external org-wide default is Read or ReadWrite, the UI API models them, and UserRecordAccess confirms the guest user can read live records. Secure guest record access means the OWD alone does not grant guests access, so something shares these records with guests that the share table does not show (or could not be read for). Any unauthenticated visitor can page through the records it reaches. That is the intent when the records are a public dataset; confirm they are. ' +
          uiApiNote,
        remediation:
          'Confirm the records guests can read are meant to be public. If not, find what shares them (guest sharing rules, manual or Apex shares, public group membership) and remove it, and remove Read from the guest profile/permission sets unless a specific public dataset is intended.',
        affectedItems: reachablePublic.map((e) => ({
          label: `${e.obj} (external OWD: ${e.owd}${e.write ? ', guest Create permission too' : ''})`,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: this.evidenceNote(e),
        })),
      });
    }
    if (unconfirmedPublic.length > 0) {
      findings.push({
        id: 'guest-object-exposure-public-owd-unconfirmed',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unconfirmedPublic.length} object(s) readable by the guest profile with a public external OWD; guest record access not confirmed`,
        detail:
          'The guest profile can read these objects and their external org-wide default is Read or ReadWrite. Since Winter \'21 secure guest record access is always enforced, so that default opens records to logged-in external users but not to guests: record sharing gives a guest a record only through a guest sharing rule or ownership. UserRecordAccess did not confirm that any guest user can read any of up to 200 sampled records, and no guest user owns any (each item\'s note says whether the probe ran). A guest sharing rule whose criteria no sampled record met can still expose other records, so confirm in the org.',
        remediation:
          'Remove Read from the guest profile/permission sets unless a specific public dataset is intended, and review the guest sharing rules on these objects. Setting the external OWD to Private also limits what logged-in external users see.',
        affectedItems: unconfirmedPublic.map((e) => ({
          label: `${e.obj} (external OWD: ${e.owd}${e.write ? ', guest Create permission too' : ''})`,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: this.evidenceNote(e),
        })),
      });
    }
    if (reachableOwned.length > 0) {
      findings.push({
        id: 'guest-object-exposure-guest-owned',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${reachableOwned.length} object(s) expose records the guest user owns`,
        detail:
          'The guest user OWNS records in these objects (typically public-form submissions created as the guest user). An owner can always read its own records, so neither a Private OWD nor secure guest record access protects them, and the UI API models the object, so all guest-owned records are readable unauthenticated in bulk. ' +
          uiApiNote,
        remediation:
          'Reassign the records the guest user owns to an internal user or queue, and remove Read on these objects from the guest profile. Since Winter \'21 the platform assigns new guest-created records to the site\'s default record owner, so most of these predate that; Web-to-Case can still leave the site guest user as case owner, so check that an assignment rule or flow reassigns new cases.',
        affectedItems: reachableOwned.map((e) => ({
          label: `${e.obj}: ${e.count} guest-owned record(s)${e.write ? ' (guest Create permission too)' : ''}`,
          url: `${baseUrl}/${e.obj}`,
          note: this.evidenceNote(e),
        })),
      });
    }
    if (reachableShared.length > 0) {
      findings.push({
        id: 'guest-object-exposure-guest-shared',
        category: this.category,
        // HIGH, not CRITICAL: a guest sharing rule is the platform's documented way to publish
        // records to a site, and nothing here says whether the records are meant to be public.
        riskLevel: 'HIGH',
        title: `${reachableShared.length} object(s) share records with unauthenticated guests`,
        detail:
          'The guest profile can read these objects, their external org-wide default is not public, and records are still shared with guests: the object\'s share table holds guest user sharing rule rows, or legacy manual, Apex or group shares naming a guest user (access granted before Winter \'21 was not removed), or UserRecordAccess confirms the guest reads a sampled record. The UI API models the object, so any unauthenticated visitor can page through the shared records. That is the intent when the records are a public dataset; confirm they are. ' +
          uiApiNote,
        remediation:
          'Confirm each object\'s shared records are meant to be public. If not, narrow or remove the guest user sharing rules (Setup → Sharing Settings), delete manual and Apex shares to the guest user, and remove the guest user from public groups and queues. Remove Read from the guest profile/permission sets unless a public dataset is intended.',
        affectedItems: reachableShared.map((e) => ({
          label: `${e.obj}${e.count !== undefined ? `: ${e.count} guest share row(s)` : ''}${e.write ? ' (guest Create permission too)' : ''}`,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: e.count !== undefined
            ? 'Share rows giving guests access found in the share table; UI-API-modelled (GraphQL-reachable)'
            : this.evidenceNote(e),
        })),
      });
    }
    if (sharingOnly.length > 0) {
      findings.push({
        id: 'guest-object-exposure-sharing-only',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${sharingOnly.length} object(s) readable in the sharing model but NOT reachable via the UI API`,
        detail:
          'The guest can read these objects in the sharing model (object permission plus guest ownership, records shared with guests, or a public OWD), but the UI API `object-info` endpoint does not model them, so they are NOT pullable through the guest GraphQL vector (this is the tier that Calendar, AuthSession, OauthToken and similar system objects fall into). This is a defense-in-depth grant to tighten, not an active bulk-exfiltration surface.',
        remediation:
          'Remove Read from the guest profile/permission sets for these objects unless specifically required. Because they are not UI-API-modelled they are lower priority than the CRITICAL findings, but a stripped guest profile should not hold these grants at all.',
        affectedItems: sharingOnly.map((e) => ({
          label: `${e.obj} (${e.kind === 'public' ? `external OWD: ${e.owd}` : e.kind === 'owned' ? `${e.count} guest-owned` : 'records shared with guests'}${e.write ? ', guest Create permission too' : ''})`,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: 'Sharing-readable; UI API object-info = not modelled (not GraphQL-reachable)',
        })),
      });
    }
    if (exposed.length === 0) {
      findings.push(this.ok(guests.length, readable.length));
    }
    return { findings };
  }

  /**
   * Probes the UI API `object-info` endpoint. Returns true if the object is
   * modelled (reachable via executeGraphQL), false if the endpoint reports it is
   * not modelled, or null if the probe could not be performed at all.
   */
  private async isUiApiModeled(ctx: AuditContext, obj: string): Promise<boolean | null> {
    if (typeof ctx.rest?.get !== 'function') return null;
    try {
      await ctx.rest.get(`/ui-api/object-info/${obj}`);
      return true;
    } catch {
      // 404 / UNSUPPORTED_OBJECT => the UI API does not model this object.
      return false;
    }
  }

  private evidenceNote(e: ExposedObject): string {
    if (e.confirmed === true) return 'Read CONFIRMED via UserRecordAccess; UI-API-modelled (GraphQL-reachable)';
    if (e.confirmed === false) return 'UI-API-modelled, but UserRecordAccess shows no guest user can read any sampled record (up to 200)';
    if (e.confirmed === 'failed') return 'UI-API-modelled (GraphQL-reachable); UserRecordAccess could not be queried, so guest read is unconfirmed';
    return 'UI-API-modelled (GraphQL-reachable); no record available to confirm guest read';
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
          : `Guest profiles can read ${readableCount} object(s), but all have a Private external OWD with no guest-owned records and no records shared with guests, so no records are bulk-readable.`,
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
