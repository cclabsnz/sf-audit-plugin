import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Patterns that indicate DML or inline SOQL is being performed
const HAS_DML = /\b(?:insert|update|delete|upsert|merge)\s+\w+|Database\.(?:insert|update|delete|upsert|merge)\s*\(/i;
const HAS_SOQL = /\[\s*SELECT\b|Database\.(?:query|queryWithBinds|countQuery)\s*\(/i;

// Patterns that indicate FLS/CRUD is being checked or enforced
const HAS_FLS = /(?:\.isAccessible\(\)|\.isCreateable\(\)|\.isUpdateable\(\)|\.isDeletable\(\)|Security\.stripInaccessible|SObjectAccessDecision|Schema\.describeSObjects|Schema\.sObjectType\.\w+\.fields)/i;

// Classes that are exempt from CRUD/FLS enforcement by design:
// batch, scheduled, and trigger handlers run in a system context
const IS_BATCH_OR_SCHEDULED = /implements\s+(?:Database\.Batchable|Schedulable|Database\.StatefulBatch|Database\.AllowsCallouts)/i;
const WITHOUT_SHARING = /\bwithout\s+sharing\b/i;

export class ApexCrudFLSCheck implements SecurityCheck {
  readonly id = 'apex-crud-fls';
  readonly name = 'Apex CRUD/FLS Enforcement';
  readonly category = 'Code Security';
  readonly description = 'Flags Apex classes that perform DML or SOQL without checking CRUD/FLS permissions: OWASP Top 10 for Salesforce';

  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const apexClassesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ApexClasses/home`;
    const apexBodies = ctx.cache.apexBodies ?? [];

    if (apexBodies.length === 0) {
      findings.push({
        id: 'apex-crud-fls-no-bodies',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Apex class bodies not available: CRUD/FLS check skipped',
        detail: 'Apex class bodies were not cached. Ensure HardcodedCredentialsCheck runs before this check.',
        remediation: 'Verify registry ordering so HardcodedCredentialsCheck (which populates apexBodies) precedes ApexCrudFLSCheck.',
      });
      return { findings };
    }

    const withoutSharingNoFls: string[] = [];
    const withDmlNoFls: string[] = [];

    // apexBodies is pre-filtered by HardcodedCredentialsCheck, which excludes @IsTest classes
    // before populating the cache. There is deliberately no second guard here: a cache miss
    // yields an empty array, not unfiltered bodies, so there is nothing for one to catch.
    for (const { name, body } of apexBodies) {
      if (!body || IS_BATCH_OR_SCHEDULED.test(body)) continue;

      const hasDml = HAS_DML.test(body);
      const hasSoql = HAS_SOQL.test(body);
      if (!hasDml && !hasSoql) continue;

      const hasFls = HAS_FLS.test(body);
      if (hasFls) continue;

      if (WITHOUT_SHARING.test(body)) {
        withoutSharingNoFls.push(name);
      } else {
        withDmlNoFls.push(name);
      }
    }

    if (withoutSharingNoFls.length > 0) {
      findings.push({
        id: 'apex-crud-fls-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${withoutSharingNoFls.length} Apex class(es) run "without sharing" and perform DML/SOQL without CRUD/FLS checks`,
        detail:
          `Apex classes declared "without sharing" bypass record-level visibility AND have no field-level or object-level permission checks, meaning any user who triggers the code can read or write any record and field regardless of their assigned permissions. This is the most exploited Salesforce access control vulnerability. OWASP Salesforce Top 10 ranks CRUD/FLS bypass as the #1 risk.`,
        remediation:
          'Refactor to use "with sharing" where possible. Add `Security.stripInaccessible()` before DML and `Schema.SObjectType.[Object].fields.[Field].isAccessible()` before displaying fields. Where "without sharing" is required for a technical reason, document the justification and tighten the scope.',
        affectedItems: withoutSharingNoFls.slice(0, 30).map((n) => ({
          label: n,
          url: apexClassesUrl,
          note: '"without sharing" + DML/SOQL + no FLS check: highest risk',
        })),
      });
    }

    if (withDmlNoFls.length > 0) {
      findings.push({
        id: 'apex-crud-fls-missing',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${withDmlNoFls.length} Apex class(es) perform DML or SOQL without CRUD/FLS permission checks`,
        detail:
          `These classes perform database operations without checking whether the running user has create, read, update, or delete permission on the relevant objects or fields. While sharing rules still apply, object and field-level access is not enforced in code. Users can potentially access or modify data beyond their intended permissions via these code paths.`,
        remediation:
          `Add CRUD checks before DML: \`Schema.SObjectType.[Object].isCreateable()\`. Use \`Security.stripInaccessible(AccessType.READABLE, records)\` before exposing query results. Consider adopting a shared FLS utility class to centralise enforcement.`,
        affectedItems: withDmlNoFls.slice(0, 30).map((n) => ({
          label: n,
          url: apexClassesUrl,
          note: 'DML/SOQL without FLS check: add Security.stripInaccessible() or isAccessible() guards',
        })),
      });
    }

    if (withoutSharingNoFls.length === 0 && withDmlNoFls.length === 0) {
      findings.push({
        id: 'apex-crud-fls-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All scanned Apex classes with DML/SOQL include CRUD/FLS permission checks',
        detail: 'No Apex classes were found performing DML or SOQL without corresponding object-level or field-level security checks. This scan covers non-test, non-batch classes in the org namespace.',
        remediation: 'Continue monitoring as new Apex classes are developed.',
      });
    }

    return { findings };
  }
}
