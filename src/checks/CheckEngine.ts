import type { SecurityCheck } from './SecurityCheck.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditResult } from '../findings/AuditResult.js';
import { buildAuditResult } from '../findings/scoring.js';

function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    id: `${check.id}-error`,
    checkId: check.id,
    category: check.category,
    riskLevel: 'INFO',
    title: `${check.name}: check failed`,
    detail: `This check encountered an error and could not complete: ${msg}`,
    remediation:
      'Review the error message and verify the running user has the required permissions.',
  };
}

export class CheckEngine {
  constructor(
    private readonly checks: SecurityCheck[],
    private readonly ctx: AuditContext,
  ) {
    this.validateCacheOrdering();
  }

  async run(
    onProgress?: (current: number, total: number, checkName: string) => void,
  ): Promise<AuditResult> {
    const findings: Finding[] = [];
    let metrics: Partial<OrgMetrics> = {};
    const total = this.checks.length;

    for (let i = 0; i < total; i++) {
      const check = this.checks[i];
      onProgress?.(i + 1, total, check.name);
      try {
        const result = await check.run(this.ctx);
        findings.push(...result.findings.map((f) => ({ ...f, checkId: check.id })));
        if (result.metrics) {
          metrics = { ...metrics, ...result.metrics };
        }
      } catch (err) {
        findings.push(buildErrorFinding(check, err));
      }
    }

    return buildAuditResult(this.ctx, findings, metrics);
  }

  private validateCacheOrdering(): void {
    const populated = new Set<keyof AuditCache>();
    for (const check of this.checks) {
      for (const key of check.dependsOnCache ?? []) {
        if (!populated.has(key)) {
          throw new Error(
            `Check '${check.name}' depends on cache key '${key}' ` +
              `but no preceding check declares it in populatesCache.`,
          );
        }
      }
      for (const key of check.populatesCache ?? []) {
        populated.add(key);
      }
    }
  }
}
