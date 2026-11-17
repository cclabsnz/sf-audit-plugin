import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isMissingObjectError } from '../support/missingObject.js';

interface RestrictionRuleRecord {
  Id: string;
  Name?: string;
  MasterLabel?: string;
  TargetEntity: string;
  EnforcementType?: string;
  IsActive: boolean;
  RecordFilter?: string;
  UserCriteria?: string;
}

export class RestrictionRulesIntegrityCheck implements SecurityCheck {
  readonly id = 'restriction-rules-integrity';
  readonly name = 'Restriction Rules Integrity & Conflict Detection';
  readonly category = 'Data Security';
  readonly description =
    'Detects inactive Restriction Rules, and active rules on one object whose user criteria are identical, so only one of them takes effect.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const rulesUrl = `${baseUrl}/lightning/setup/ObjectManager/home`;

    let rules: RestrictionRuleRecord[] = [];
    try {
      rules = await ctx.tooling.query<RestrictionRuleRecord>(
        'SELECT Id, MasterLabel, TargetEntity, IsActive, EnforcementType, UserCriteria FROM RestrictionRule',
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
        remediation: 'When deploying Restriction Rules, keep them active and give each rule on an object user criteria that match a distinct set of users.',
      });
      return { findings };
    }

    // 1. Check for inactive restriction rules
    const inactiveRules = rules.filter((r) => r.IsActive === false);

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

    // 2. Active rules on one object whose user criteria are the same. Several active rules per
    // object are normal (up to two in Enterprise and Developer Edition, five in Performance and
    // Unlimited), each scoped to different users. Salesforce expects at most one rule's
    // userCriteria to be true for a given user, does not validate it, and observes only one when
    // two apply. Different criteria can still overlap, but that needs the users' data to decide,
    // so only identical criteria are a certain conflict.
    // https://developer.salesforce.com/docs/atlas.en-us.restriction_rules.meta/restriction_rules/restriction_rules_considerations.htm
    // https://developer.salesforce.com/docs/atlas.en-us.restriction_rules.meta/restriction_rules/restriction_rules_about.htm
    // Whitespace is dropped only outside quoted literals, and case is kept, so 'Sales Rep' and
    // 'SalesRep', or two record ids that differ only in case, are not taken for the same criteria.
    const normalise = (c?: string): string =>
      (c ?? '').split(/('(?:[^'\\]|\\.)*')/).map((part, i) => (i % 2 ? part : part.replace(/\s+/g, ''))).join('');
    // Only restriction rules restrict access. Scoping rules set default filters, and FieldRestrict
    // and D360_Restrict are other rule kinds, so a duplicated pair of them is not an access failure.
    const NOT_RESTRICTING = new Set(['Scoping', 'FieldRestrict', 'D360_Restrict']);
    const activeRulesByCriteria = new Map<string, RestrictionRuleRecord[]>();
    for (const r of rules.filter((r) => r.IsActive === true && !NOT_RESTRICTING.has(r.EnforcementType ?? ''))) {
      const key = `${r.TargetEntity}\u0000${r.EnforcementType ?? ''}\u0000${normalise(r.UserCriteria)}`;
      const list = activeRulesByCriteria.get(key) ?? [];
      list.push(r);
      activeRulesByCriteria.set(key, list);
    }

    const conflictingEntities = [...activeRulesByCriteria.values()]
      .filter((group) => group.length > 1)
      .map((group): [string, RestrictionRuleRecord[]] => [group[0].TargetEntity, group]);

    if (conflictingEntities.length > 0) {
      findings.push({
        id: 'restriction-rules-conflicting',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${conflictingEntities.length} set(s) of active Restriction Rules share the same user criteria on one object`,
        detail:
          'When more than one active restriction rule applies to a user on the same object, Salesforce observes only one of them and does not say which. These rules have identical user criteria, so every user they target gets one rule\'s record filter and the other is ignored. The records those users see may not be the ones you intended.',
        remediation:
          'Give each active rule on the object user criteria that match a distinct set of users, or merge the rules into one.',
        affectedItems: conflictingEntities.map(([entity, entityRules]) => ({
          label: `${entity} (${entityRules.length} active rules, same user criteria)`,
          url: rulesUrl,
          note: `Rules: ${entityRules.map((r) => r.MasterLabel || r.Name || r.Id).join(', ')}; user criteria: ${entityRules[0].UserCriteria || 'none'}`,
        })),
      });
    }

    if (inactiveRules.length === 0 && conflictingEntities.length === 0) {
      findings.push({
        id: 'restriction-rules-integrity-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All Restriction Rules are active and none share user criteria on the same object',
        detail: `${rules.length} Restriction Rule(s) inspected; all rules are active and no two active rules on one object have the same user criteria.`,
        remediation: 'Keep each active rule on an object scoped to a distinct set of users.',
      });
    }

    return { findings };
  }
}
