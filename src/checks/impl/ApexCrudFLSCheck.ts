import type { AuditContext } from '@cclabsnz/sf-core';
import { testApexPattern } from '@cclabsnz/sf-core';
import { apexApiVersions, apexCode, codeWithoutStrings, DML_AS_USER, OMITTED_SHARING_ENFORCED_FROM, usesSystemMode } from '../support/apexAccess.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Patterns that indicate DML or inline SOQL is being performed
const HAS_DML = /\b(?:insert|update|delete|upsert|undelete|merge)\s+\w+|Database\.(?:insert|update|delete|upsert|undelete|merge)\w*\s*\(/i;
// SOQL and SOSL, inline or dynamic.
const HAS_SOQL = /\[\s*(?:SELECT|FIND)\b|Database\.(?:query|queryWithBinds|countQuery|countQueryWithBinds|getQueryLocator|getQueryLocatorWithBinds|getCursor|getCursorWithBinds)\s*\(|\bSearch\.(?:query|find)\s*\(/i;

// Patterns that indicate FLS/CRUD is being checked or enforced
// USER_MODE enforces CRUD/FLS (and sharing) on the query or DML it is attached to.
const HAS_FLS = /(?:\.isAccessible\(\)|\.isCreateable\(\)|\.isUpdateable\(\)|\.isDeletable\(\)|Security\.stripInaccessible|SObjectAccessDecision|Schema\.describeSObjects|Schema\.sObjectType\.\w+\.fields|\bWITH\s+USER_MODE\b|\bAccessLevel\s*\.\s*USER_MODE\b)/i;

// SYSTEM_MODE (WITH SYSTEM_MODE, AccessLevel.SYSTEM_MODE, `insert as system`) switches CRUD/FLS
// off for that operation; sharing still follows the class keyword. It is never enforcement,
// whatever else the class does, and batch or scheduled classes are no exception (spec RULE-002).

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
    const systemMode: { name: string; withoutSharing: boolean }[] = [];
    // From API 67.0 (Summer '26) SOQL, SOSL, DML and Database methods run in user mode unless they
    // say otherwise, so a class saved at 67.0 or later enforces CRUD/FLS by default (spec RULE-009).
    // SYSTEM_MODE is still reported above that default.
    const versions = await apexApiVersions(ctx);
    let userModeByDefault = 0;

    // apexBodies is pre-filtered by HardcodedCredentialsCheck, which excludes @IsTest classes
    // before populating the cache. There is deliberately no second guard here: a cache miss
    // yields an empty array, not unfiltered bodies, so there is nothing for one to catch.
    for (const { name, body: raw } of apexBodies) {
      if (!raw) continue;
      // Patterns are matched against code only: "WITH USER_MODE" in a comment enforces nothing.
      const body = apexCode(raw);

      // SYSTEM_MODE only ever qualifies a query or DML, so it is reported before, and regardless
      // of, the pattern gate below: a form that gate does not know must not slip through (RULE-002).
      if (usesSystemMode(raw)) {
        systemMode.push({ name, withoutSharing: testApexPattern(body, WITHOUT_SHARING) });
        continue;
      }

      const hasDml = testApexPattern(body, HAS_DML);
      const hasSoql = testApexPattern(body, HAS_SOQL);
      if (!hasDml && !hasSoql) continue;

      if (testApexPattern(body, IS_BATCH_OR_SCHEDULED)) continue;

      if ((versions.get(name.toLowerCase()) ?? 0) >= OMITTED_SHARING_ENFORCED_FROM) {
        userModeByDefault++;
        continue;
      }

      // Enforcement must be code, not text: 'WITH USER_MODE' inside a debug string enforces nothing.
      const enforcementCode = codeWithoutStrings(raw);
      const hasFls = testApexPattern(enforcementCode, HAS_FLS) || testApexPattern(enforcementCode, DML_AS_USER);
      if (hasFls) continue;

      if (testApexPattern(body, WITHOUT_SHARING)) {
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
          'Enforce object and field permissions with `WITH USER_MODE`, or `Security.stripInaccessible()` before DML and `Schema.SObjectType.[Object].fields.[Field].isAccessible()` before displaying fields. "with sharing" alone does not do this: it enforces record sharing only. Declare "with sharing" too where possible, and where "without sharing" is required for a technical reason, document the justification and tighten the scope.',
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

    if (systemMode.length > 0) {
      findings.push({
        id: 'apex-crud-fls-system-mode',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${systemMode.length} Apex class(es) switch off CRUD/FLS with SYSTEM_MODE`,
        detail:
          'WITH SYSTEM_MODE and AccessLevel.SYSTEM_MODE run a query or DML without checking the user\'s object and field permissions. Record sharing still follows the class keyword, so this exposes fields and objects the user cannot otherwise see on records they can reach; in a "without sharing" class it exposes every record too.',
        remediation:
          'Use WITH USER_MODE / AccessLevel.USER_MODE wherever the operation serves a user. Where SYSTEM_MODE is genuinely needed, keep it to the narrowest query and strip fields with Security.stripInaccessible() before returning results.',
        affectedItems: systemMode.slice(0, 30).map(({ name, withoutSharing }) => ({
          label: name,
          url: apexClassesUrl,
          note: withoutSharing ? 'SYSTEM_MODE in a "without sharing" class: no CRUD/FLS and no sharing' : 'SYSTEM_MODE: CRUD/FLS not enforced',
        })),
      });
    }

    if (withoutSharingNoFls.length === 0 && withDmlNoFls.length === 0 && systemMode.length === 0) {
      findings.push({
        id: 'apex-crud-fls-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All scanned Apex classes with DML/SOQL include CRUD/FLS permission checks',
        detail: `No Apex classes were found performing DML or SOQL without corresponding object-level or field-level security checks. This scan covers non-test, non-batch classes in the org namespace.${userModeByDefault > 0 ? ` ${userModeByDefault} class(es) saved at API 67.0 or later rely on user mode, the default for their queries and DML from that version.` : ''}`,
        remediation: 'Continue monitoring as new Apex classes are developed.',
      });
    }

    return { findings };
  }
}
