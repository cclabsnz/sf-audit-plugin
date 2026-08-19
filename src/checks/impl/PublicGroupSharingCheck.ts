import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GroupRecord {
  Id: string;
  Name: string;
  Type: string;
}

interface SharingCountRecord {
  UserOrGroupId: string;
  cnt: number;
}

const SHARE_TABLES = ['AccountShare', 'CaseShare', 'ContactShare', 'OpportunityShare'] as const;

export class PublicGroupSharingCheck implements SecurityCheck {
  readonly id = 'public-group-sharing';
  readonly name = 'Public Group Sharing Exposure';
  readonly category = 'Sharing & Visibility';
  readonly description = 'Finds sharing rules that grant broad access to All Internal Users';

  readonly dependsOnCache = ['healthCloudInstalled'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const sharingRulesUrl = `${baseUrl}/lightning/setup/SecuritySharing/page`;

    const groups = await ctx.soql.queryAll<GroupRecord>(
      "SELECT Id, Name, Type FROM Group WHERE Type = 'AllInternal'"
    );

    if (groups.length === 0) {
      findings.push({
        id: 'public-group-sharing-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No records shared to All Internal Users groups via sharing rules',
        detail: 'No sharing rules were found targeting the "All Internal Users" group on key objects.',
        remediation:
          'Continue to avoid broad sharing rules. Periodically review sharing configuration as the org grows.',
      });
      return { findings };
    }

    interface Exposure {
      shareTable: string;
      groupName: string;
      count: number;
    }

    // One query per share table with IN clause — reduces G×4 queries to 4 regardless of group count
    const groupIdList = groups.map((g) => `'${g.Id}'`).join(', ');
    const groupNameMap = new Map(groups.map((g) => [g.Id, g.Name]));

    const exposures: Exposure[] = [];
    // Which share tables could not be read. An object may be absent from the org edition or
    // simply not permitted; either way the check did not see it, and the conclusion has to say
    // so rather than count silence as evidence of no sharing.
    const unreadable: string[] = [];
    for (const shareTable of SHARE_TABLES) {
      try {
        const result = await ctx.soql.query<SharingCountRecord>(
          `SELECT UserOrGroupId, COUNT(Id) cnt
           FROM ${shareTable}
           WHERE UserOrGroupId IN (${groupIdList})
             AND RowCause = 'SharingRule'
           GROUP BY UserOrGroupId`
        );
        for (const r of result.records) {
          if (r.cnt > 0) {
            exposures.push({
              shareTable,
              groupName: groupNameMap.get(r.UserOrGroupId) ?? r.UserOrGroupId,
              count: r.cnt,
            });
          }
        }
      } catch {
        unreadable.push(shareTable);
      }
    }

    if (exposures.length > 0) {
      const objectCount = new Set(exposures.map((e) => e.shareTable)).size;
      const riskLevel = ctx.cache.healthCloudInstalled === true ? 'HIGH' : 'MEDIUM';

      findings.push({
        id: 'public-group-sharing-exposure',
        category: this.category,
        riskLevel,
        title: `All Internal Users group shares records across ${objectCount} object type(s)`,
        affectedItems: exposures.map((e) => ({
          label: `${e.shareTable} → ${e.groupName}`,
          url: sharingRulesUrl,
          note: `${e.count} sharing rule(s): replace with targeted group or role-based sharing`,
        })),
        detail:
          'Sharing rules targeting "All Internal Users" expose records to every active internal user in the org.',
        remediation:
          'Replace "All Internal Users" sharing rules with more targeted public groups or role-based sharing.',
      });
    } else if (unreadable.length === SHARE_TABLES.length) {
      // Nothing was readable, so "no exposure found" would be an assertion about data never seen.
      findings.push({
        id: 'public-group-sharing-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Sharing to All Internal Users could not be evaluated',
        detail:
          `None of the share tables (${SHARE_TABLES.join(', ')}) could be queried, so whether sharing rules target the "All Internal Users" group is unknown. ${groups.length} such group(s) exist in this org.`,
        remediation:
          'Grant the audit user read access to the share tables and re-run, or review sharing rules manually in Setup → Sharing Settings.',
      });
    } else {
      const checked = SHARE_TABLES.filter((s) => !unreadable.includes(s));
      findings.push({
        id: 'public-group-sharing-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No records shared to All Internal Users groups via sharing rules',
        detail: unreadable.length > 0
          ? `No sharing rules targeting the "All Internal Users" group were found on ${checked.join(', ')}. ${unreadable.join(', ')} could not be queried and were not checked.`
          : 'No sharing rules were found targeting the "All Internal Users" group on key objects.',
        remediation:
          'Continue to avoid broad sharing rules. Periodically review sharing configuration as the org grows.',
      });
    }

    return { findings };
  }
}
