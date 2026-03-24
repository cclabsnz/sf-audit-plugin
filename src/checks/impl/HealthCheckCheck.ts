import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface HealthCheckRecord { Score: number; }
interface HealthCheckRiskRecord {
  RiskType: string; Setting: string; SettingGroup: string;
  OrgValue: string; StandardValue: string;
}
interface PackageLicenseRecord { NamespacePrefix: string; }

export class HealthCheckCheck implements SecurityCheck {
  readonly id = 'health-check';
  readonly name = 'Security Health Check';
  readonly category = 'Health Check';
  readonly description = 'Reads the Salesforce Health Check score and flags individual risk items';
  readonly populatesCache = ['healthCheckRisks', 'healthCloudInstalled'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Health Cloud detection
    const pkgRows = await ctx.soql.queryAll<PackageLicenseRecord>(
      "SELECT NamespacePrefix FROM PackageLicense WHERE NamespacePrefix = 'HealthCloudGA'"
    );
    ctx.cache.healthCloudInstalled = pkgRows.length > 0;

    // Health check score
    const scoreRows = await ctx.tooling.query<HealthCheckRecord>(
      'SELECT Score FROM SecurityHealthCheck'
    );
    const score = scoreRows[0]?.Score ?? 0;

    const scoreRisk = score < 50 ? 'CRITICAL' : score < 70 ? 'HIGH' : score < 85 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'health-check-score',
      category: this.category,
      riskLevel: scoreRisk,
      title: `Salesforce Security Health Check Score: ${score}/100`,
      detail: `The Salesforce Security Health Check scored ${score}/100. Scores below 85 indicate security configuration gaps that should be addressed.`,
      remediation: 'Review the Security Health Check in Setup → Security Center → Health Check.',
    });

    // HIGH_RISK items
    const highRisks = await ctx.tooling.query<HealthCheckRiskRecord>(
      "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='HIGH_RISK'"
    );
    ctx.cache.healthCheckRisks = [
      ...highRisks.map((r) => ({ setting: r.Setting, riskType: r.RiskType, value: r.OrgValue, score: 10 })),
    ];

    if (highRisks.length > 0) {
      findings.push({
        id: 'health-check-high-risk',
        category: this.category,
        riskLevel: 'HIGH',
        title: `Security Health Check: ${highRisks.length} High-Risk Setting(s) Require Attention`,
        detail: 'One or more settings deviate from Salesforce security recommendations at the high-risk level.',
        remediation: 'Address each highlighted setting in Setup → Security Center → Health Check.',
        affectedItems: highRisks.map((r) => `${r.Setting}: org=${r.OrgValue}, recommended=${r.StandardValue}`),
      });
    }

    // MEDIUM_RISK items
    const mediumRisks = await ctx.tooling.query<HealthCheckRiskRecord>(
      "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='MEDIUM_RISK'"
    );
    ctx.cache.healthCheckRisks = [
      ...(ctx.cache.healthCheckRisks ?? []),
      ...mediumRisks.map((r) => ({ setting: r.Setting, riskType: r.RiskType, value: r.OrgValue, score: 4 })),
    ];

    if (mediumRisks.length > 0) {
      findings.push({
        id: 'health-check-medium-risk',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `Security Health Check: ${mediumRisks.length} Medium-Risk Setting(s) Need Review`,
        detail: 'One or more settings deviate from Salesforce security recommendations at the medium-risk level.',
        remediation: 'Review and address medium-risk settings in Setup → Security Center → Health Check.',
        affectedItems: mediumRisks.map((r) => `${r.Setting}: org=${r.OrgValue}, recommended=${r.StandardValue}`),
      });
    }

    return { findings, metrics: { healthCheckScore: score } };
  }
}
