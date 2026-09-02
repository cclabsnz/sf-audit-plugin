import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser {
  Id: string;
  Username: string;
}
interface PsaRec {
  AssigneeId: string;
  PermissionSetId: string;
  PermissionSet: {
    Label: string;
    PermissionsViewAllUsers: boolean;
  } | null;
}
interface EntityDef {
  QualifiedApiName: string;
  InternalSharingModel: string | null;
  ExternalSharingModel: string | null;
}
interface ObjectPermission {
  ParentId: string;
  SobjectType: string;
  PermissionsRead: boolean;
}

// External sharing models that expose every User record to external (portal/guest) users.
const PUBLIC_OWD = new Set(['Read', 'ReadWrite', 'ReadSelect']);

/**
 * Detects whether unauthenticated guests can see OTHER USERS — the identity-
 * enumeration surface that the object-level guest checks miss, because `User` is
 * not in their fixed object lists and is rarely surfaced by a guest profile's
 * ObjectPermissions.
 *
 * Three independent paths reach the same outcome, so all three are graded:
 *   - "View All Users" on a guest profile/permission set: total bypass of User
 *     sharing, every User record readable regardless of OWD (CRITICAL).
 *   - A public EXTERNAL org-wide default on `User` (Read/ReadWrite): every User
 *     record is visible to portal and guest users by sharing alone (HIGH).
 *   - An explicit Read grant on `User` in a guest permission set, which combined
 *     with any sharing path turns the roster into a queryable directory (HIGH).
 *
 * The INTERNAL sharing model is reported for context but never graded: `User`
 * ships as Public Read Only in every org, so grading it would fire on every audit.
 *
 * One leg is deliberately not asserted: the "Portal User Visibility" / "Community
 * User Visibility" checkboxes in Setup → Sharing Settings are not exposed to any
 * read API this plugin uses, so a clean result carries an explicit manual-
 * verification note rather than claiming more certainty than the data supports.
 * The Experience Cloud per-site equivalent ("Let guest users see other members")
 * IS API-readable and is covered by `guest-site-options`.
 */
export class GuestUserVisibilityCheck implements SecurityCheck {
  readonly id = 'guest-user-visibility';
  readonly name = 'Guest Visibility of Other Users';
  readonly category = 'Access Control';
  readonly description =
    'Checks whether unauthenticated guests can see other User records — via View All Users, a public external OWD on User, or a guest Read grant on the User object';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const sharingUrl = `${baseUrl}/lightning/setup/SecuritySharing/page`;
    const permSetUrl = `${baseUrl}/lightning/setup/PermSets/home`;

    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>(
        "SELECT Id, Username FROM User WHERE UserType = 'Guest' AND IsActive = true",
      );
    } catch {
      findings.push(this.inconclusive('guest-user-visibility-inaccessible', 'Guest users could not be queried'));
      return { findings };
    }

    if (guests.length === 0) {
      findings.push({
        id: 'guest-user-visibility-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users',
        detail: 'There are no active guest users, so no unauthenticated visitor can enumerate the org\'s User records.',
        remediation:
          'If an Experience Cloud or Sites site is added later, keep the external org-wide default on User set to Private and keep "View All Users" off every guest profile.',
      });
      return { findings };
    }

    const inIds = guests.map((g) => `'${g.Id}'`).join(', ');
    let psa: PsaRec[];
    try {
      psa = await ctx.soql.queryAll<PsaRec>(
        `SELECT AssigneeId, PermissionSetId, PermissionSet.Label, PermissionSet.PermissionsViewAllUsers
         FROM PermissionSetAssignment WHERE AssigneeId IN (${inIds})`,
      );
    } catch {
      findings.push(
        this.inconclusive('guest-user-visibility-perms-inaccessible', 'Guest permission sets could not be queried'),
      );
      return { findings };
    }

    const guestById = new Map(guests.map((g) => [g.Id, g]));
    const labelById = new Map(psa.filter((p) => p.PermissionSet).map((p) => [p.PermissionSetId, p.PermissionSet!.Label]));

    // 1. "View All Users" — bypasses User sharing entirely.
    const viewAll = psa.filter((p) => p.PermissionSet?.PermissionsViewAllUsers);
    if (viewAll.length > 0) {
      findings.push({
        id: 'guest-user-visibility-view-all-users',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${viewAll.length} guest permission grant(s) include "View All Users"`,
        detail:
          '"View All Users" lets the holder read every User record in the org regardless of the sharing model. On a guest user this hands an unauthenticated visitor the full staff roster — usernames, email addresses, roles, manager relationships and phone numbers — which is a ready-made target list for credential stuffing, phishing and social engineering against named administrators.',
        remediation:
          'Remove "View All Users" from the guest profile and from every permission set assigned to a guest user. Guests must never hold org-wide user visibility.',
        affectedItems: viewAll.slice(0, 30).map((p) => ({
          label: `${guestById.get(p.AssigneeId)?.Username ?? p.AssigneeId} — via ${p.PermissionSet!.Label}`,
          url: permSetUrl,
          note: 'View All Users granted: remove immediately',
        })),
      });
    }

    // 2. External org-wide default on User.
    let userEntity: EntityDef | undefined;
    try {
      const defs = await ctx.soql.queryAll<EntityDef>(
        "SELECT QualifiedApiName, InternalSharingModel, ExternalSharingModel FROM EntityDefinition WHERE QualifiedApiName = 'User'",
      );
      userEntity = defs.find((d) => d.QualifiedApiName === 'User');
    } catch {
      // OWD unreadable — the other two signals are still graded below.
    }

    const external = userEntity?.ExternalSharingModel ?? null;
    const internal = userEntity?.InternalSharingModel ?? null;
    if (external && PUBLIC_OWD.has(external)) {
      findings.push({
        id: 'guest-user-visibility-owd',
        category: this.category,
        riskLevel: 'HIGH',
        title: `The User object has a public external org-wide default (${external})`,
        detail:
          'The external org-wide default on User controls what portal and guest users can see of other users. Set to Read or Read/Write, every User record in the org is visible to any external or unauthenticated visitor by sharing alone — no permission grant required — turning the site into a directory of internal staff.',
        remediation:
          'Set the User object\'s Default External Access to Private in Setup → Sharing Settings. Where portal users legitimately need to see each other, grant it narrowly with sharing sets or user sharing rules rather than an open default.',
        affectedItems: [
          {
            label: 'User',
            url: sharingUrl,
            note: `External OWD: ${external}${internal ? ` (internal: ${internal})` : ''} — ${guests.length} active guest user(s)`,
          },
        ],
      });
    }

    // 3. Explicit Read grant on the User object in a guest permission set.
    const psIds = [...new Set(psa.map((p) => p.PermissionSetId))];
    let userRead: ObjectPermission[] = [];
    if (psIds.length > 0) {
      try {
        const psIn = psIds.map((i) => `'${i}'`).join(', ');
        userRead = await ctx.soql.queryAll<ObjectPermission>(
          `SELECT ParentId, SobjectType, PermissionsRead FROM ObjectPermissions
           WHERE ParentId IN (${psIn}) AND SobjectType = 'User' AND PermissionsRead = true`,
        );
      } catch {
        // Object permissions unreadable — the other two signals still stand.
      }
    }
    if (userRead.length > 0) {
      findings.push({
        id: 'guest-user-visibility-object-read',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${userRead.length} guest permission grant(s) give Read access to the User object`,
        detail:
          'A guest permission set or profile grants Read on the User object. Object-level read is what makes User queryable at all for a guest; combined with any sharing path that exposes records — a public external OWD, a user sharing rule, or guest member visibility on an Experience site — it turns the User table into an enumerable directory reachable over the UI API.',
        remediation:
          'Remove Read on the User object from guest profiles and guest permission sets. Where site components must show a name, expose it through Apex that returns only the specific fields required.',
        affectedItems: userRead.slice(0, 30).map((p) => ({
          label: labelById.get(p.ParentId) ?? p.ParentId,
          url: permSetUrl,
          note: 'Read on User granted: remove from guest permissions',
        })),
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'guest-user-visibility-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${guests.length} active guest user(s); no user-enumeration path found`,
        detail:
          `No guest holds "View All Users", the User object's external org-wide default is ${external ?? 'not publicly readable'}, and no guest permission set grants Read on User.${internal ? ` The internal model is ${internal}, which is the platform default and is not graded here.` : ''} One control is not API-readable: the "Portal User Visibility" and "Community User Visibility" checkboxes in Sharing Settings are exposed to no read API this plugin uses, so that leg needs manual confirmation.`,
        remediation:
          'In Setup → Sharing Settings, confirm the portal/community user visibility checkboxes are off unless a member directory is intended, and keep the User external default Private as sites are added. The per-site equivalent ("Let guest users see other members") is covered by the Experience Cloud Guest Site Options check.',
        affectedItems: [{ label: 'Sharing Settings', url: sharingUrl, note: 'Manual verification of user visibility checkboxes' }],
      });
    }

    return { findings };
  }

  private inconclusive(id: string, what: string): Finding {
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather the data needed to evaluate guest visibility of other users.',
      remediation: 'Grant the audit user View Setup and Configuration and re-run.',
    };
  }
}
