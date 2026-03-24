// STUB — replaced with full implementation in Task 7
import type { AuditContext } from '../context/AuditContext.js';
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
): AuditResult {
  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore: 100,
    grade: 'A',
  };
}
