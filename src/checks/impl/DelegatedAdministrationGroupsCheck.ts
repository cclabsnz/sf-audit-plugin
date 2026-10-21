import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface DelegateGroupRecord {
  Id: string;
  Name?: string;
  DeveloperName?: string;
  Description?: string | null;
}

interface DelegateGroupMemberRecord {
  Id: string;
  DelegateGroupId: string;
  UserOrGroupId: string;
}

interface UserRecord {
  Id: string;
  Username: string;
  Profile?: { Name?: string };
  IsActive?: boolean;
}

export class DelegatedAdministrationGroupsCheck implements SecurityCheck {
  readonly id = 'delegated-administration-groups';
  readonly name = 'Delegated Administration Groups';
  readonly category = 'Privileged Access';
  readonly description =
    'Identifies unmonitored Delegated Admin Groups that grant shadow-admin privileges outside profiles and permission sets.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/DelegateGroups/home`;

    let groups: DelegateGroupRecord[] = [];
    try {
      // DelegateGroup and DelegateGroupMember are served by the Tooling API only.
      groups = await ctx.tooling.query<DelegateGroupRecord>(
        'SELECT Id, DeveloperName FROM DelegateGroup',
      );
    } catch (err) {
      // This object exists in every org, so a failure is lack of access, never an absent feature.
      findings.push({
        id: 'delegated-administration-groups-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Delegated Administration Groups could not be queried',
        detail: `Failed to query DelegateGroup: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "View Setup and Configuration" to inspect delegated admin groups.',
      });
      return { findings };
    }

    if (groups.length === 0) {
      findings.push({
        id: 'delegated-administration-groups-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Delegated Administration Groups found',
        detail: 'Zero DelegateGroup records are configured in this org.',
        remediation: 'Continue avoiding unmonitored delegated administration groups.',
      });
      return { findings };
    }

    // Query members of delegated admin groups
    let members: DelegateGroupMemberRecord[] = [];
    members = await ctx.tooling.query<DelegateGroupMemberRecord>(
      'SELECT Id, DelegateGroupId, UserOrGroupId FROM DelegateGroupMember',
    );

    // Collect user names if members exist
    const userIds = members
      .map((m) => m.UserOrGroupId)
      .filter((id): id is string => Boolean(id && id.startsWith('005')));
    let userMap = new Map<string, string>();
    if (userIds.length > 0) {
      const users = await ctx.soql.queryAll<UserRecord>(
        `SELECT Id, Username, Profile.Name FROM User WHERE Id IN ('${userIds.join("','")}')`,
      );
      for (const u of users) {
        userMap.set(u.Id, `${u.Username} (${u.Profile?.Name ?? 'Unknown Profile'})`);
      }
    }

    findings.push({
      id: 'delegated-administration-groups-active',
      category: this.category,
      riskLevel: 'HIGH',
      title: `${groups.length} Delegated Administration Group(s) grant unmonitored shadow-admin privileges`,
      detail:
        'Delegated Administration groups operate completely outside Profiles, Permission Sets, and Permission Set Groups. A user with a standard read-only profile assigned to a DelegateGroup can create users, reset passwords, unlock accounts, assign permission sets, and log in as users in their subordinate role hierarchy—effectively serving as an invisible Shadow Admin that standard privilege audits miss.',
      remediation:
        'Review all members and assigned grants in Setup → Delegated Administration. Ensure all delegated administrators are known, assignable permission sets are tightly scoped, and remove obsolete groups.',
      affectedItems: groups.map((g) => {
        const groupMembers = members.filter((m) => m.DelegateGroupId === g.Id);
        const memberDesc = groupMembers
          .map((m) => userMap.get(m.UserOrGroupId) ?? m.UserOrGroupId)
          .join(', ');
        return {
          label: g.DeveloperName || g.Name || g.Id,
          url: setupUrl,
          note: memberDesc ? `Members: ${memberDesc}` : 'Active delegated administration group',
        };
      }),
    });

    return { findings };
  }
}
