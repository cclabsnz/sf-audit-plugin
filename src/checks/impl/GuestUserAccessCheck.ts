import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { guestPrincipals, guestReadsSample, guestShareCount } from '../support/guestShares.js';

interface UserRecord {
  Id: string;
  ProfileId: string;
  Username: string;
}

interface ObjectPermissionRecord {
  ParentId: string;
  SobjectType: string;
  PermissionsCreate: boolean;
  PermissionsEdit: boolean;
  PermissionsDelete: boolean;
  PermissionsRead: boolean;
}

const STANDARD_OBJECTS = ['Account', 'Contact', 'Case', 'Lead', 'Opportunity'] as const;
const HEALTH_CLOUD_OBJECTS = ['CarePlan__c', 'CareTeamMember__c', 'EhrPatient__c'] as const;
// The standard objects whose guest shares this check reports; GuestObjectExposureCheck covers the rest.
const SHARED_OBJECTS = ['Account', 'Case', 'Contact', 'Opportunity'] as const;

export class GuestUserAccessCheck implements SecurityCheck {
  readonly id = 'guest-user-access';
  readonly name = 'Guest User Access';
  readonly category = 'Access Control';
  readonly description = 'Audits object permissions and sharing rules granted to unauthenticated guest users';

  readonly dependsOnCache = ['healthCloudInstalled'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const guestUsers = await ctx.soql.queryAll<UserRecord>(
      "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true"
    );

    if (guestUsers.length === 0) {
      findings.push({
        id: 'guest-user-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users found',
        detail:
          'There are no active guest users in this org, so guest user security misconfiguration is not a concern.',
        remediation:
          'If an Experience Cloud site is added in the future, ensure guest user permissions are properly restricted.',
      });
      return { findings };
    }

    // ObjectPermissions.ParentId is a permission set Id, never a profile Id: a profile's object
    // permissions sit on the permission set it owns. The guests' assignments cover that one and any
    // permission set assigned to a guest. (Filtering ParentId on profile Ids matched nothing.)
    const userById = new Map(guestUsers.map((u) => [u.Id, u]));
    const guestsByPermSet = new Map<string, UserRecord[]>();
    try {
      const assignments = await ctx.soql.queryAll<{ AssigneeId: string; PermissionSetId: string }>(
        `SELECT AssigneeId, PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId IN (${guestUsers.map((u) => `'${u.Id}'`).join(', ')})`,
      );
      for (const a of assignments) {
        const u = userById.get(a.AssigneeId);
        if (!u) continue;
        guestsByPermSet.set(a.PermissionSetId, [...(guestsByPermSet.get(a.PermissionSetId) ?? []), u]);
      }
    } catch {
      // Unreadable: object access is then not judged (no read or write finding).
    }
    const permSetIds = [...guestsByPermSet.keys()];

    // Determine which objects to check (include HC objects only if installed)
    const objectsToCheck: string[] = [...STANDARD_OBJECTS];
    if (ctx.cache.healthCloudInstalled === true) {
      objectsToCheck.push(...HEALTH_CLOUD_OBJECTS);
    }

    // SBS-CPORTAL-002: guest users must have NO access to business objects — not even read.
    interface WriteViolation {
      userId: string;
      username: string;
      sobjectType: string;
      canCreate: boolean;
      canEdit: boolean;
      canDelete: boolean;
    }
    interface ReadViolation {
      userId: string;
      username: string;
      sobjectType: string;
    }
    const writeViolations: WriteViolation[] = [];
    const readViolations: ReadViolation[] = [];

    // One batch query: every guest permission set × every object.
    const objectList = objectsToCheck.map((o) => `'${o}'`).join(', ');
    // Objects some guest can read, for the share-table fallback below; null when unknown.
    let guestReadable: Set<string> | null = permSetIds.length === 0 ? new Set() : null;
    if (permSetIds.length > 0) try {
      const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
        `SELECT ParentId, SobjectType, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsRead
         FROM ObjectPermissions
         WHERE ParentId IN (${permSetIds.map((id) => `'${id}'`).join(', ')})
           AND SobjectType IN (${objectList})`
      );
      guestReadable = new Set(perms.filter((p) => p.PermissionsRead).map((p) => p.SobjectType));
      for (const perm of perms) {
        const profileUsers = guestsByPermSet.get(perm.ParentId) ?? [];
        if (perm.PermissionsCreate || perm.PermissionsEdit || perm.PermissionsDelete) {
          for (const u of profileUsers) {
            writeViolations.push({
              userId: u.Id,
              username: u.Username,
              sobjectType: perm.SobjectType,
              canCreate: perm.PermissionsCreate,
              canEdit: perm.PermissionsEdit,
              canDelete: perm.PermissionsDelete,
            });
          }
        } else if (perm.PermissionsRead) {
          for (const u of profileUsers) {
            readViolations.push({
              userId: u.Id,
              username: u.Username,
              sobjectType: perm.SobjectType,
            });
          }
        }
      }
    } catch {
      // Skip on error
    }

    // Share rows giving guests access: guest user sharing rules (and the parent access they imply),
    // and legacy manual, Apex and group shares that Winter '21 did not remove (support/guestShares).
    // When the share table shows none (Contact controlled by its parent, a share the table does not
    // show) or cannot be read, UserRecordAccess on a sample is asked instead.
    interface SharingExposure {
      shareTable: string;
      count?: number;
    }
    const sharingExposures: SharingExposure[] = [];
    const guestIds = guestUsers.map((u) => u.Id);
    const guestIdList = guestIds.map((i) => `'${i}'`).join(', ');
    const principals = await guestPrincipals(ctx, guestIds);
    for (const obj of SHARED_OBJECTS) {
      // Null: the share table could not be read (or the object is not shareable in this org).
      const count = await guestShareCount(ctx, obj, principals);
      if (count !== null && count > 0) {
        sharingExposures.push({ shareTable: `${obj}Share`, count });
        continue;
      }
      // The fallback asks only where a guest can read the object (a read without object access is
      // no exposure; unknown access is asked), and not where the guest owns records: owned records
      // are always readable and are reported as guest-object-exposure-guest-owned.
      if (guestReadable !== null && !guestReadable.has(obj)) continue;
      if (await this.guestOwns(ctx, obj, guestIdList)) continue;
      if ((await guestReadsSample(ctx, obj, guestIds)) === true) sharingExposures.push({ shareTable: `${obj}Share` });
    }

    // Emit findings based on what was found
    if (writeViolations.length > 0) {
      findings.push({
        id: 'guest-user-write-access',
        category: this.category,
        // Writing is tampering, not the disclosure the rest of this check reports.
        threats: { stride: ['T', 'I'] },
        riskLevel: 'CRITICAL',
        title: 'Guest user profile(s) have write access to Salesforce objects',
        affectedItems: writeViolations.map((v) => {
          const actions = [v.canCreate && 'Create', v.canEdit && 'Edit', v.canDelete && 'Delete']
            .filter(Boolean)
            .join('/');
          return {
            label: `${v.username}: ${v.sobjectType}`,
            url: `${baseUrl}/${v.userId}`,
            note: `Can ${actions}: remove immediately`,
          };
        }),
        detail:
          'Unauthenticated users (guests) with write access to standard objects represents a critical misconfiguration. SBS-CPORTAL-002 requires guest users have no access to business objects.',
        remediation:
          'Remove all Create, Edit, and Delete permissions from guest user profiles immediately. Guest users should have no object access.',
      });
    }

    // SBS-CPORTAL-002: read access also violates the standard
    if (readViolations.length > 0) {
      findings.push({
        id: 'guest-user-read-access',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${readViolations.length} object(s) grant read access to guest user(s)`,
        affectedItems: readViolations.map((v) => ({
          label: `${v.username}: ${v.sobjectType}`,
          url: `${baseUrl}/${v.userId}`,
          note: 'Read access: remove from guest profile; restrict to authenticated users only',
        })),
        detail:
          'SBS-CPORTAL-002 requires guest users be limited to authentication flows only with no access to business objects. Read access exposes data to unauthenticated visitors.',
        remediation:
          'Remove Read permissions on all business objects from guest user profiles. Data access should only be granted after authentication.',
      });
    }

    if (sharingExposures.length > 0) {
      const count = sharingExposures.reduce((sum, e) => sum + (e.count ?? 0), 0);
      const confirmedOnly = sharingExposures.filter((e) => e.count === undefined).length;
      findings.push({
        id: 'guest-user-sharing-exposure',
        category: this.category,
        riskLevel: 'HIGH',
        title: count > 0
          ? `${count} share row(s) give guest users access to Account, Case, Contact or Opportunity records${confirmedOnly > 0 ? `, and guests read records on ${confirmedOnly} more object(s)` : ''}`
          : `Guest users can read Account, Case, Contact or Opportunity records on ${confirmedOnly} object(s)`,
        affectedItems: sharingExposures.map((e) => ({
          label: e.shareTable,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: e.count !== undefined
            ? `${e.count} share row(s) giving guests access: review the guest sharing rules and legacy shares`
            : 'No share row seen, but UserRecordAccess confirms a guest user reads a sampled record',
        })),
        detail:
          'Records on these objects are shared with guest users: by guest user sharing rules (and the parent access they imply), or by manual, Apex-managed or public-group shares made before Winter \'21, which the platform did not remove. Any unauthenticated visitor to the site can read the shared records.',
        remediation:
          'Confirm the shared records are meant to be public. If not, narrow or remove the guest user sharing rules (Setup → Sharing Settings), delete manual and Apex shares to the guest user, and remove the guest user from public groups and queues.',
      });
    }

    if (writeViolations.length === 0 && readViolations.length === 0 && sharingExposures.length === 0) {
      const count = guestUsers.length;
      findings.push({
        id: 'guest-user-baseline',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count} active guest user(s) have live site access`,
        affectedItems: guestUsers.map((u) => ({
          label: u.Username,
          url: `${baseUrl}/${u.Id}`,
          note: 'Periodically review guest permissions and sharing configuration',
        })),
        detail:
          'Guest users are present in this org. While no write access or overly permissive sharing rules were found, guest access should be periodically reviewed.',
        remediation:
          'Regularly review guest user profile permissions and sharing configurations as they represent an unauthenticated attack surface.',
      });
    }

    return { findings };
  }

  private async guestOwns(ctx: AuditContext, obj: string, guestIdList: string): Promise<boolean> {
    try {
      return (await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${obj} WHERE OwnerId IN (${guestIdList})`)).totalSize > 0;
    } catch {
      return false;
    }
  }
}
