import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

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

interface SharingCountRecord {
  UserOrGroupId: string;
  cnt: number;
}

const STANDARD_OBJECTS = ['Account', 'Contact', 'Case', 'Lead', 'Opportunity'] as const;
const HEALTH_CLOUD_OBJECTS = ['CarePlan__c', 'CareTeamMember__c', 'EhrPatient__c'] as const;
const SHARE_TABLES = ['AccountShare', 'CaseShare', 'ContactShare', 'OpportunityShare'] as const;

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

    // Build profile → users map and unique profile ID list for batch queries
    const profileUserMap = new Map<string, UserRecord[]>();
    for (const user of guestUsers) {
      const list = profileUserMap.get(user.ProfileId) ?? [];
      list.push(user);
      profileUserMap.set(user.ProfileId, list);
    }
    const profileIds = [...profileUserMap.keys()];

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

    // Single batch query: all profiles × all objects (replaces per-profile loop)
    const profileIdList = profileIds.map((id) => `'${id}'`).join(', ');
    const objectList = objectsToCheck.map((o) => `'${o}'`).join(', ');
    try {
      const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
        `SELECT ParentId, SobjectType, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsRead
         FROM ObjectPermissions
         WHERE ParentId IN (${profileIdList})
           AND SobjectType IN (${objectList})`
      );
      for (const perm of perms) {
        const profileUsers = profileUserMap.get(perm.ParentId) ?? [];
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

    // Check sharing rules targeting guest users.
    // One query per share table (not per user) using GROUP BY — reduces N×4 to 4 queries.
    interface SharingExposure {
      shareTable: string;
      count: number;
    }
    const sharingExposures: SharingExposure[] = [];
    const userIdList = guestUsers.map((u) => `'${u.Id}'`).join(', ');

    for (const shareTable of SHARE_TABLES) {
      try {
        const result = await ctx.soql.query<SharingCountRecord>(
          `SELECT UserOrGroupId, COUNT(Id) cnt
           FROM ${shareTable}
           WHERE UserOrGroupId IN (${userIdList})
             AND RowCause = 'SharingRule'
           GROUP BY UserOrGroupId`
        );
        const totalCount = result.records.reduce((sum, r) => sum + (r.cnt ?? 0), 0);
        if (totalCount > 0) {
          sharingExposures.push({ shareTable, count: totalCount });
        }
      } catch {
        // Object may not be accessible — skip silently
      }
    }

    // Emit findings based on what was found
    if (writeViolations.length > 0) {
      findings.push({
        id: 'guest-user-write-access',
        category: this.category,
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
      const count = sharingExposures.reduce((sum, e) => sum + e.count, 0);
      findings.push({
        id: 'guest-user-sharing-exposure',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} object sharing rule(s) expose records to guest users`,
        affectedItems: sharingExposures.map((e) => ({
          label: e.shareTable,
          url: `${baseUrl}/lightning/setup/SecuritySharing/page`,
          note: `${e.count} sharing rule(s): review and remove guest-targeting rules`,
        })),
        detail:
          'Sharing rules targeting guest users can expose internal records to unauthenticated visitors.',
        remediation:
          'Review and remove sharing rules that grant guest users access to Salesforce records. Use Experience Cloud sites with explicit data access controls instead.',
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
}
