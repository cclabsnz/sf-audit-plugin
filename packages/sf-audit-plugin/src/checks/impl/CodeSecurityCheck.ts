import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexCoverageRecord {
  PercentCovered: number;
}

interface CountResult {
  expr0?: number;
}

// SBS-CODE-002: dynamic SOQL with string concatenation is the primary SOQL injection vector.
// Pattern: Database.query( or Database.countQuery( followed by a + operator before the closing paren/semicolon.
const DYNAMIC_SOQL_INJECTION = /Database\.(query|countQuery)\s*\([^;)]*\+[^;)]*[);]/gi;
// Also catch String.escapeSingleQuotes absence heuristic: raw variable use inside query strings
const UNSAFE_DYNAMIC_QUERY = /\[\s*SELECT\b[^\]]*:(?!'\s*\])[^,\]]+[+][^\]]*\]/gi;

export class CodeSecurityCheck implements SecurityCheck {
  readonly id = 'code-security';
  readonly name = 'Code Security and Coverage';
  readonly category = 'Code Security';
  readonly description = 'Reports org-wide Apex test coverage, class/trigger counts, and flags potential SOQL injection patterns';

  // Reuse Apex bodies cached by HardcodedCredentialsCheck — no extra API call needed
  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Fire all three independent Tooling queries in parallel.
    // COUNT(Id) expr0 puts the result in records[0].expr0; COUNT() without a field
    // puts it in totalSize which is not in the typed return value.
    const [classCountResults, triggerCountResults, coverageResults] = await Promise.all([
      ctx.tooling.query<CountResult>('SELECT COUNT(Id) expr0 FROM ApexClass WHERE NamespacePrefix = null'),
      ctx.tooling.query<CountResult>('SELECT COUNT(Id) expr0 FROM ApexTrigger WHERE NamespacePrefix = null'),
      ctx.tooling.query<ApexCoverageRecord>('SELECT PercentCovered FROM ApexOrgWideCoverage'),
    ]);
    const classCount = classCountResults[0]?.expr0 ?? 0;
    const triggerCount = triggerCountResults[0]?.expr0 ?? 0;

    if (coverageResults.length > 0) {
      const coverage = coverageResults[0].PercentCovered;

      let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'LOW';
      if (coverage < 75) {
        riskLevel = 'HIGH';
      } else if (coverage < 85) {
        riskLevel = 'MEDIUM';
      }

      findings.push({
        id: 'code-coverage',
        category: this.category,
        riskLevel,
        title: `Apex test coverage: ${coverage}%`,
        detail: `Org-wide Apex test coverage is ${coverage}%. Salesforce requires 75% minimum to deploy but higher coverage indicates better code quality and security.`,
        remediation: 'Increase test coverage, particularly for security-sensitive Apex classes handling authentication, data access, and external integrations.',
      });
    } else {
      findings.push({
        id: 'code-coverage-unavailable',
        category: this.category,
        riskLevel: 'INFO',
        title: `Apex code inventory: ${classCount} class(es), ${triggerCount} trigger(s)`,
        detail: `Code coverage data is not available for this org. The org has ${classCount} custom Apex classes (including test classes) and ${triggerCount} custom Apex triggers.`,
        remediation: 'Run Apex tests in this org to generate coverage data. Ensure all Apex code has adequate test coverage.',
      });
    }

    // SBS-CODE-002: scan cached Apex bodies for potential SOQL injection patterns.
    // Bodies are already fetched by HardcodedCredentialsCheck — no additional API call.
    // apexBodies is pre-filtered by HardcodedCredentialsCheck to exclude test classes
    const apexBodies = ctx.cache.apexBodies ?? [];
    const soqlInjectionClasses: string[] = [];

    for (const { name, body } of apexBodies) {
      if (!body) continue;

      DYNAMIC_SOQL_INJECTION.lastIndex = 0;
      UNSAFE_DYNAMIC_QUERY.lastIndex = 0;

      if (DYNAMIC_SOQL_INJECTION.test(body) || UNSAFE_DYNAMIC_QUERY.test(body)) {
        soqlInjectionClasses.push(name);
      }
    }

    if (soqlInjectionClasses.length > 0) {
      const apexClassesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ApexClasses/home`;
      findings.push({
        id: 'soql-injection-risk',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${soqlInjectionClasses.length} Apex class(es) contain potential SOQL injection patterns`,
        detail:
          'Dynamic SOQL built with string concatenation (Database.query(... + variable ...)) is vulnerable to SOQL injection if the variable originates from user input. SBS-CODE-002 requires pre-merge static analysis to catch these patterns.',
        remediation:
          'Replace string concatenation in dynamic SOQL with bind variables (:variable syntax). For unavoidable dynamic clauses, sanitize all user-supplied values with String.escapeSingleQuotes().',
        affectedItems: soqlInjectionClasses.map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: 'Review Database.query() / Database.countQuery() calls for user-controlled input',
        })),
      });
    }

    return {
      findings,
      metrics: {
        apexClassCount: classCount,
        apexTriggerCount: triggerCount,
        codeCoveragePercent: coverageResults[0]?.PercentCovered ?? 0,
      },
    };
  }
}
