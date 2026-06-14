import type { SecurityCheck } from './SecurityCheck.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditResult } from '../findings/AuditResult.js';
import type { ScoringConfig } from '../findings/ScoringConfig.js';
import { buildAuditResult } from '../findings/scoring.js';
import { getComplianceTags } from '../compliance/resolve.js';
import { ChainEngine } from '../chains/ChainEngine.js';

const PERMISSION_ERROR_CODES = new Set([
  'INSUFFICIENT_ACCESS_RIGHTS',
  'INVALID_CROSS_REFERENCE_KEY',
  'ENTITY_IS_INACCESSIBLE',
  'INVALID_FIELD',
  'INVALID_TYPE',
]);

function isPermissionError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const code = (err as Error & { errorCode?: string }).errorCode ?? '';
  const msg = err.message ?? '';
  return (
    PERMISSION_ERROR_CODES.has(code) ||
    msg.includes('INSUFFICIENT_ACCESS') ||
    msg.includes('insufficient access') ||
    msg.includes('INVALID_FIELD') ||
    msg.includes('entity type cannot be queried')
  );
}

function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  const inconclusive = isPermissionError(err);
  return {
    id: `${check.id}-error`,
    checkId: check.id,
    category: check.category,
    riskLevel: 'INFO',
    title: `${check.name}: ${inconclusive ? 'insufficient permissions' : 'check failed'}`,
    detail: inconclusive
      ? `This check could not gather evidence because the running user lacks the required permissions: ${msg}`
      : `This check encountered an error and could not complete: ${msg}`,
    remediation: inconclusive
      ? 'Grant the audit user the permissions listed in the tool documentation, then re-run the audit.'
      : 'Review the error message and verify the running user has the required permissions.',
    inconclusive: inconclusive || undefined,
  };
}

export class CheckEngine {
  constructor(
    private readonly checks: SecurityCheck[],
    private readonly ctx: AuditContext,
    private readonly scoringConfig?: ScoringConfig,
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
        const tags = getComplianceTags(check.id);
        findings.push(...result.findings.map((f) => ({ ...f, checkId: check.id, complianceTags: tags })));
        if (result.metrics) {
          metrics = { ...metrics, ...result.metrics };
        }
      } catch (err) {
        findings.push(buildErrorFinding(check, err));
      }
    }

    const attackChains = new ChainEngine().correlate(findings);
    return buildAuditResult(this.ctx, findings, metrics, this.scoringConfig, attackChains);
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
