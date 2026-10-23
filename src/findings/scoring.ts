import type { Finding } from './Finding.js';
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { AuditResult } from './AuditResult.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import { EMPTY_METRICS } from '@cclabsnz/sf-core';
import { DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig } from './ScoringConfig.js';
import type { AttackChain } from '../chains/AttackChain.js';
import { evidenceCoverage, MIN_COVERAGE_FOR_A } from './coverage.js';

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

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * Why the audit got this grade: the first condition of the next better grade it failed, or, for
 * an A, that it met every condition. Thresholds come from the scoring config, so custom ones are
 * explained in their own terms.
 */
function explainGrade(
  grade: Grade,
  config: ScoringConfig,
  healthScore: number,
  counts: { criticalCount: number; highCount: number; mediumCount: number; chains: Record<'CRITICAL' | 'HIGH' | 'MEDIUM', number> },
  gradeCapped: boolean,
  coveragePercent: number,
): string {
  if (gradeCapped) {
    return `B: evidence coverage ${coveragePercent}% is below the ${MIN_COVERAGE_FOR_A}% needed for an A`;
  }
  const order: Grade[] = ['A', 'B', 'C', 'D', 'F'];
  const better = order[order.indexOf(grade) - 1];
  if (!better) return `A: health score ${healthScore}/100 with no condition for a higher grade unmet`;
  const t = config.gradeThresholds[better];
  // "3 CRITICAL findings", or "5 CRITICAL (3 findings, 2 attack chains)" when chains count too.
  const what = (n: number, level: 'CRITICAL' | 'HIGH' | 'MEDIUM') => {
    const c = counts.chains[level];
    return c === 0 ? plural(n, `${level} finding`) : `${n} ${level} (${plural(n - c, 'finding')}, ${plural(c, 'attack chain')})`;
  };
  const allows = (max: number) => (max === 0 ? 'none' : `at most ${max}`);
  if (t.maxCritical !== undefined && counts.criticalCount > t.maxCritical) {
    return `${grade}: ${what(counts.criticalCount, 'CRITICAL')} (${better} allows ${allows(t.maxCritical)})`;
  }
  if (t.maxHigh !== undefined && counts.highCount > t.maxHigh) {
    return `${grade}: ${what(counts.highCount, 'HIGH')} (${better} allows ${allows(t.maxHigh)})`;
  }
  if (t.maxMedium !== undefined && counts.mediumCount > t.maxMedium) {
    return `${grade}: ${what(counts.mediumCount, 'MEDIUM')} (${better} allows ${allows(t.maxMedium)})`;
  }
  if (t.minScore !== undefined && healthScore < t.minScore) {
    return `${grade}: health score ${healthScore}/100 (${better} needs ${t.minScore})`;
  }
  return `${grade}: did not meet the conditions for ${better}`;
}

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
  attackChains: AttackChain[] = [],
): AuditResult {
  // Passed, inconclusive and waived findings carry no penalty — exclude from numerator.
  // Passed findings remain in maxPossible so a broad passing audit still dilutes real failures.
  // Unassessed ones do not: a check that gathered no evidence must not improve the score.
  const unassessed = (f: Finding) => Boolean(f.inconclusive || f.notAssessed);
  const totalScore = findings.reduce(
    (sum, f) => {
      if (f.passed || f.waived || unassessed(f)) return sum;
      return sum + (f.checkId !== undefined ? (config.checkWeights[f.checkId] ?? config.riskScores[f.riskLevel]) : config.riskScores[f.riskLevel]);
    },
    0,
  );
  const chainScore = attackChains.reduce((sum, c) => sum + config.riskScores[c.severity], 0);
  const totalWithChains = totalScore + chainScore;
  const maxPossible = (findings.filter((f) => !unassessed(f)).length + attackChains.length) * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalWithChains / Math.max(maxPossible, 1)) * 100),
  );

  // Only open findings and named chains set the grade. A potential chain is inferred from
  // capability overlap, not matched to a known attack, so it is reported but does not grade.
  const named = attackChains.filter((c) => c.confidence !== 'potential');
  const open = findings.filter((f) => !f.waived && !f.passed && !unassessed(f));
  const count = (level: Finding['riskLevel']) =>
    open.filter((f) => f.riskLevel === level).length + named.filter((c) => c.severity === level).length;
  const criticalCount = count('CRITICAL');
  const highCount = count('HIGH');
  const mediumCount = count('MEDIUM');

  const grades: Grade[] = ['A', 'B', 'C', 'D'];
  let grade: Grade = 'F';
  for (const g of grades) {
    if (meetsConditions(config.gradeThresholds[g], healthScore, criticalCount, highCount, mediumCount)) {
      grade = g;
      break;
    }
  }

  const waivedFindings = findings.filter((f) => f.waived);

  // A run that could not see enough of the org is never graded A. Coverage is reported either way.
  const coverage = evidenceCoverage(findings);
  const gradeCapped = grade === 'A' && coverage.percent < MIN_COVERAGE_FOR_A;
  if (gradeCapped) grade = 'B';

  const chainCount = (level: Finding['riskLevel']) => named.filter((c) => c.severity === level).length;
  const gradeReason = explainGrade(
    grade,
    config,
    healthScore,
    { criticalCount, highCount, mediumCount, chains: { CRITICAL: chainCount('CRITICAL'), HIGH: chainCount('HIGH'), MEDIUM: chainCount('MEDIUM') } },
    gradeCapped,
    coverage.percent,
  );

  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    instanceUrl: ctx.orgInfo.instanceUrl,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore,
    grade,
    gradeReason,
    attackChains,
    waivedFindings: waivedFindings.length > 0 ? waivedFindings : undefined,
    coverage: { ...coverage, gradeCapped },
  };
}
