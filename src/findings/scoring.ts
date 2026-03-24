import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { RiskLevel } from './RiskLevel.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scoringConfig = JSON.parse(fs.readFileSync(path.join(pluginRoot, 'config', 'scoring.json'), 'utf-8')) as {
  riskScores: Record<RiskLevel, number>;
};
const RISK_SCORES = scoringConfig.riskScores;

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
): AuditResult {
  const totalScore = findings.reduce((sum, f) => sum + RISK_SCORES[f.riskLevel], 0);
  const maxPossible = findings.length * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalScore / Math.max(maxPossible, 1)) * 100),
  );

  const criticalCount = findings.filter((f) => f.riskLevel === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.riskLevel === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.riskLevel === 'MEDIUM').length;
  const totalFindings = findings.length;

  let grade: AuditResult['grade'];
  
  if (criticalCount > 0) {
    grade = 'F';
  } else if (healthScore < 40 && totalFindings > 5) {
    // Many findings with very low health score = F
    grade = 'F';
  } else if (highCount > 3) {
    grade = 'D';
  } else if (highCount > 1) {
    grade = 'C';
  } else if (mediumCount > 3) {
    grade = 'B';
  } else if (healthScore < 40) {
    grade = 'F';
  } else if (healthScore < 55) {
    grade = 'D';
  } else if (healthScore < 70) {
    grade = 'C';
  } else if (healthScore < 85) {
    grade = 'B';
  } else {
    grade = 'A';
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
