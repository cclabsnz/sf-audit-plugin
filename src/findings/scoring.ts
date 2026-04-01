import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import type { AuditContext } from '../context/AuditContext.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';
import { DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig } from './ScoringConfig.js';

type Grade = AuditResult['grade'];

function meetsConditions(
  conditions: ScoringConfig['gradeThresholds'][Grade],
  healthScore: number,
  criticalCount: number,
  highCount: number,
  mediumCount: number,
): boolean {
  if (conditions.minScore !== undefined && healthScore < conditions.minScore) return false;
  if (conditions.maxCritical !== undefined && criticalCount > conditions.maxCritical) return false;
  if (conditions.maxHigh !== undefined && highCount > conditions.maxHigh) return false;
  if (conditions.maxMedium !== undefined && mediumCount > conditions.maxMedium) return false;
  return true;
}

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
): AuditResult {
  const totalScore = findings.reduce(
    (sum, f) => sum + (config.checkWeights[f.checkId ?? ''] ?? config.riskScores[f.riskLevel]),
    0,
  );
  const maxPossible = findings.length * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalScore / Math.max(maxPossible, 1)) * 100),
  );

  const criticalCount = findings.filter((f) => f.riskLevel === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.riskLevel === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.riskLevel === 'MEDIUM').length;

  const grades: Grade[] = ['A', 'B', 'C', 'D'];
  let grade: Grade = 'F';
  for (const g of grades) {
    if (meetsConditions(config.gradeThresholds[g], healthScore, criticalCount, highCount, mediumCount)) {
      grade = g;
      break;
    }
  }

  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore,
    grade,
  };
}
