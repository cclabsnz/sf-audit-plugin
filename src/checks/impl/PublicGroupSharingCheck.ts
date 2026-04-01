import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GroupRecord {
  Id: string;
  Name: string;
  Type: string;
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

    const exposures: Exposure[] = [];

    for (const group of groups) {
      for (const shareTable of SHARE_TABLES) {
        try {
          const result = await ctx.soql.query<Record<string, never>>(
            `SELECT COUNT() FROM ${shareTable} WHERE UserOrGroupId = '${group.Id}' AND RowCause = 'SharingRule'`
          );
          if (result.totalSize > 0) {
            exposures.push({ shareTable, groupName: group.Name, count: result.totalSize });
          }
        } catch {
          // Object may not exist or not be accessible — skip silently
        }
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
          note: `${e.count} sharing rule(s) — replace with targeted group or role-based sharing`,
        })),
        detail:
          'Sharing rules targeting "All Internal Users" expose records to every active internal user in the org.',
        remediation:
          'Replace "All Internal Users" sharing rules with more targeted public groups or role-based sharing.',
      });
    } else {
      findings.push({
        id: 'public-group-sharing-none',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No records shared to All Internal Users groups via sharing rules',
        detail: 'No sharing rules were found targeting the "All Internal Users" group on key objects.',
        remediation:
          'Continue to avoid broad sharing rules. Periodically review sharing configuration as the org grows.',
      });
    }

    return { findings };
  }
}
