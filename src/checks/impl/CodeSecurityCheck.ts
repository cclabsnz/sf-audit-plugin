import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexCoverageRecord {
  PercentCovered: number;
}

interface CountResult {
  expr0?: number;
}

export class CodeSecurityCheck implements SecurityCheck {
  readonly id = 'code-security';
  readonly name = 'Code Security and Coverage';
  readonly category = 'Code Security';
  readonly description = 'Reports org-wide Apex test coverage percentage and class/trigger counts';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Query class and trigger counts using Tooling API
    const classCountResults = await ctx.tooling.query<CountResult>(
      "SELECT COUNT() FROM ApexClass WHERE NamespacePrefix = null AND IsTest = false"
    );
    const classCount = classCountResults[0]?.expr0 ?? 0;

    const triggerCountResults = await ctx.tooling.query<CountResult>(
      'SELECT COUNT() FROM ApexTrigger WHERE NamespacePrefix = null'
    );
    const triggerCount = triggerCountResults[0]?.expr0 ?? 0;

    // Query coverage
    const coverageResults = await ctx.tooling.query<ApexCoverageRecord>(
      'SELECT PercentCovered FROM ApexOrgWideCoverage'
    );

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
        detail: `Code coverage data is not available for this org. The org has ${classCount} custom Apex classes and ${triggerCount} custom Apex triggers.`,
        remediation: 'Run Apex tests in this org to generate coverage data. Ensure all Apex code has adequate test coverage.',
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
