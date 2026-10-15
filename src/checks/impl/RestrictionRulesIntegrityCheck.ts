import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface RestrictionRuleRecord {
  Id: string;
  Name?: string;
  MasterLabel?: string;
  TargetEntity: string;
  EnforcementType?: string;
  Active: boolean;
  RecordFilter?: string;
  UserCriteria?: string;
}

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

export class RestrictionRulesIntegrityCheck implements SecurityCheck {
  readonly id = 'restriction-rules-integrity';
  readonly name = 'Restriction Rules Integrity & Conflict Detection';
  readonly category = 'Data Security';
  readonly description =
    'Detects inactive or conflicting Restriction Rules on sensitive standard and custom objects.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const rulesUrl = `${baseUrl}/lightning/setup/ObjectManager/home`;

    let rules: RestrictionRuleRecord[] = [];
    try {
      rules = await ctx.tooling.query<RestrictionRuleRecord>(
        'SELECT Id, TargetEntity, Active, EnforcementType FROM RestrictionRule',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'restriction-rules-integrity-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'Restriction Rules are not enabled or no rules configured',
          detail: 'RestrictionRule tooling object is not accessible or not in use.',
          remediation: 'No action required.',
        });
        return { findings };
      }
      findings.push({
        id: 'restriction-rules-integrity-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Restriction Rules could not be queried',
        detail: `Failed to query RestrictionRule: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "View Setup and Configuration" and Tooling API access.',
      });
      return { findings };
    }

    if (rules.length === 0) {
      findings.push({
        id: 'restriction-rules-integrity-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Restriction Rules configured',
        detail: 'Zero RestrictionRule records configured across standard and custom objects.',
        remediation: 'When deploying Restriction Rules, ensure they remain active and avoid multiple conflicting rules on the same entity.',
      });
      return { findings };
    }

    // 1. Check for inactive restriction rules
    const inactiveRules = rules.filter((r) => r.Active === false);

    if (inactiveRules.length > 0) {
      findings.push({
        id: 'restriction-rules-inactive',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${inactiveRules.length} inactive Restriction Rule(s) detected`,
        detail:
          'Inactive Restriction Rules (often disabled temporarily during testing or maintenance and forgotten) leave the underlying object protected only by Org-Wide Defaults. If the object OWD is Public Read/Write or Public Read Only, deactivating the Restriction Rule immediately and silently exposes the entire table to all users.',
        remediation:
          'Re-activate necessary Restriction Rules or delete obsolete rules to prevent false assumptions of record isolation.',
        affectedItems: inactiveRules.map((r) => ({
          label: `${r.TargetEntity}: ${r.MasterLabel || r.Name || r.Id}`,
          url: rulesUrl,
          note: 'Restriction Rule is INACTIVE',
        })),
      });
    }

    // 2. Check for multiple active rules on the same TargetEntity (Salesforce anti-pattern)
    const activeRulesByEntity = new Map<string, RestrictionRuleRecord[]>();
    for (const r of rules.filter((r) => r.Active === true)) {
      const list = activeRulesByEntity.get(r.TargetEntity) ?? [];
      list.push(r);
      activeRulesByEntity.set(r.TargetEntity, list);
    }

    const conflictingEntities = [...activeRulesByEntity.entries()].filter(
      ([, entityRules]) => entityRules.length > 1,
    );

    if (conflictingEntities.length > 0) {
      findings.push({
        id: 'restriction-rules-conflicting',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${conflictingEntities.length} object(s) have multiple active Restriction Rules (conflicting evaluation)`,
        detail:
          'Salesforce Restriction Rules evaluate with first-match / OR logic across multiple rules. Defining multiple active restriction rules on the same object creates non-deterministic or overly broad access where a user matching any one rule gains visibility, breaking least-privilege scoping.',
        remediation:
          'Consolidate multiple Restriction Rules per entity into a single unified rule with clear record and user criteria.',
        affectedItems: conflictingEntities.map(([entity, entityRules]) => ({
          label: `${entity} (${entityRules.length} active rules)`,
          url: rulesUrl,
          note: `Multiple rules: ${entityRules.map((r) => r.MasterLabel || r.Name || r.Id).join(', ')}`,
        })),
      });
    }

    if (inactiveRules.length === 0 && conflictingEntities.length === 0) {
      findings.push({
        id: 'restriction-rules-integrity-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All Restriction Rules are active with single-rule entity isolation',
        detail: `${rules.length} Restriction Rule(s) inspected; all rules are active and no entity-level rule conflicts detected.`,
        remediation: 'Maintain single active restriction rules per object.',
      });
    }

    return { findings };
  }
}
