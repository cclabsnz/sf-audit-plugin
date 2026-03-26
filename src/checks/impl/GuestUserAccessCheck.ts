import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface UserRecord {
  Id: string;
  ProfileId: string;
  Username: string;
}

interface ObjectPermissionRecord {
  SobjectType: string;
  PermissionsCreate: boolean;
  PermissionsEdit: boolean;
  PermissionsRead: boolean;
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
        title: 'No active guest users found',
        detail:
          'There are no active guest users in this org, so guest user security misconfiguration is not a concern.',
        remediation:
          'If an Experience Cloud site is added in the future, ensure guest user permissions are properly restricted.',
      });
      return { findings };
    }

    // Determine which objects to check
    const objectsToCheck: string[] = [...STANDARD_OBJECTS];
    if (ctx.cache.healthCloudInstalled === true) {
      objectsToCheck.push(...HEALTH_CLOUD_OBJECTS);
    }

    // Collect write access violations
    interface WriteViolation {
      userId: string;
      username: string;
      sobjectType: string;
      canCreate: boolean;
      canEdit: boolean;
    }
    const writeViolations: WriteViolation[] = [];

    // Collect unique profile IDs to avoid re-querying
    const profileIds = [...new Set(guestUsers.map((u) => u.ProfileId))];

    for (const profileId of profileIds) {
      // Find which user(s) belong to this profile
      const profileUsers = guestUsers.filter((u) => u.ProfileId === profileId);

      // Query standard objects for this profile
      const standardObjectList = STANDARD_OBJECTS.map((o) => `'${o}'`).join(',');
      try {
        const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
          `SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '${profileId}' AND SobjectType IN (${standardObjectList})`
        );
        for (const perm of perms) {
          if (perm.PermissionsCreate || perm.PermissionsEdit) {
            for (const u of profileUsers) {
              writeViolations.push({
                userId: u.Id,
                username: u.Username,
                sobjectType: perm.SobjectType,
                canCreate: perm.PermissionsCreate,
                canEdit: perm.PermissionsEdit,
              });
            }
          }
        }
      } catch {
        // Skip on error
      }

      // Check Health Cloud objects if applicable
      if (ctx.cache.healthCloudInstalled === true) {
        for (const obj of HEALTH_CLOUD_OBJECTS) {
          try {
            const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
              `SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '${profileId}' AND SobjectType = '${obj}'`
            );
            for (const perm of perms) {
              if (perm.PermissionsCreate || perm.PermissionsEdit) {
                for (const u of profileUsers) {
                  writeViolations.push({
                    userId: u.Id,
                    username: u.Username,
                    sobjectType: perm.SobjectType,
                    canCreate: perm.PermissionsCreate,
                    canEdit: perm.PermissionsEdit,
                  });
                }
              }
            }
          } catch {
            // Object may not exist — skip silently
          }
        }
      }
    }

    // Check sharing rules targeting guest users
    interface SharingExposure {
      shareTable: string;
      count: number;
    }
    const sharingExposures: SharingExposure[] = [];

    for (const user of guestUsers) {
      for (const shareTable of SHARE_TABLES) {
        try {
          const result = await ctx.soql.query<Record<string, never>>(
            `SELECT COUNT() FROM ${shareTable} WHERE UserOrGroupId = '${user.Id}' AND RowCause = 'SharingRule'`
          );
          if (result.totalSize > 0) {
            const existing = sharingExposures.find((e) => e.shareTable === shareTable);
            if (existing) {
              existing.count += result.totalSize;
            } else {
              sharingExposures.push({ shareTable, count: result.totalSize });
            }
          }
        } catch {
          // Object may not be accessible — skip silently
        }
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
          const actions = [v.canCreate && 'Create', v.canEdit && 'Edit']
            .filter(Boolean)
            .join('/');
          return {
            label: `${v.username} — ${v.sobjectType}`,
            url: `${baseUrl}/${v.userId}`,
            note: `Can ${actions} — remove immediately`,
          };
        }),
        detail:
          'Unauthenticated users (guests) with write access to standard objects represents a critical misconfiguration.',
        remediation:
          'Remove all Create and Edit permissions from guest user profiles immediately. Guest users should have minimal or no object access.',
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
          url: `${baseUrl}/lightning/setup/SecuritySharingRules/page`,
          note: `${e.count} sharing rule(s) — review and remove guest-targeting rules`,
        })),
        detail:
          'Sharing rules targeting guest users can expose internal records to unauthenticated visitors.',
        remediation:
          'Review and remove sharing rules that grant guest users access to Salesforce records. Use Experience Cloud sites with explicit data access controls instead.',
      });
    }

    if (writeViolations.length === 0 && sharingExposures.length === 0) {
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
