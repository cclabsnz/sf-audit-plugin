import type { SecurityCheck } from './SecurityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AuditCache } from '@cclabsnz/sf-core';
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { AuditResult } from '../findings/AuditResult.js';
import type { ScoringConfig } from '../findings/ScoringConfig.js';
import { buildAuditResult } from '../findings/scoring.js';
import { getComplianceTags } from '../compliance/resolve.js';
import { threatsFor, withAttack } from '../threats/resolve.js';
import { ChainEngine } from '../chains/ChainEngine.js';
import type { WaiverLoader } from '../waivers/WaiverLoader.js';
import { applyWaivers } from '../waivers/applyWaivers.js';
import { permissionLabelsFor } from '../preflight/permissions.js';

const ACCESS_ERROR_CODES = new Set([
  'INSUFFICIENT_ACCESS_RIGHTS',
  'INSUFFICIENT_ACCESS_OR_READONLY',
  'INVALID_CROSS_REFERENCE_KEY',
  'ENTITY_IS_INACCESSIBLE',
]);

const REJECTION_ERROR_CODES = new Set(['INVALID_FIELD', 'INVALID_TYPE', 'MALFORMED_QUERY']);

const PERMISSIONS_DOC = 'https://github.com/cclabsnz/sf-audit-plugin/blob/main/PERMISSIONS.md';

type ErrorKind = 'access' | 'rejected' | 'failed';

/**
 * Why a check threw. A query the org rejects (unknown field or object, an unfilterable field,
 * bad syntax) is not an access problem, even though a field hidden by field-level security is
 * also reported as an unknown column: telling an admin to grant access sends them the wrong way.
 */
function classifyError(err: unknown): ErrorKind {
  if (!(err instanceof Error)) return 'failed';
  const code = (err as Error & { errorCode?: string }).errorCode ?? '';
  const msg = err.message ?? '';
  if (ACCESS_ERROR_CODES.has(code) || /INSUFFICIENT_ACCESS|insufficient access|entity type cannot be queried/i.test(msg)) {
    return 'access';
  }
  if (
    REJECTION_ERROR_CODES.has(code) ||
    /INVALID_FIELD|INVALID_TYPE|MALFORMED_QUERY|No such column|is not supported|can not be filtered|alias is reserved/i.test(msg)
  ) {
    return 'rejected';
  }
  return 'failed';
}

function accessRemediation(check: SecurityCheck): string {
  const labels = permissionLabelsFor(check);
  const named = labels.length > 0 ? `This check needs ${labels.join(' and ')}. ` : '';
  return (
    `${named}Run \`sf audit preflight\` to see which permissions the audit user is missing, and ` +
    `assign the read-only permission set described in PERMISSIONS.md (${PERMISSIONS_DOC}), then re-run the audit.`
  );
}

function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  const kind = classifyError(err);
  const base = { id: `${check.id}-error`, checkId: check.id, category: check.category, riskLevel: 'INFO' as const };
  // A check that threw gathered no evidence, whatever the cause.
  if (kind === 'access') {
    return {
      ...base,
      title: `${check.name}: insufficient permissions`,
      detail: `This check could not gather evidence because the org denied the audit user access: ${msg}`,
      remediation: accessRemediation(check),
      inconclusive: true,
      notAssessed: true,
    };
  }
  if (kind === 'rejected') {
    return {
      ...base,
      title: `${check.name}: query rejected by the org`,
      detail:
        `The org rejected this check's query, so it gathered no evidence. Salesforce said: ${msg}. ` +
        'The object or field may not exist in this edition or API version, or field-level security may hide it from the audit user.',
      remediation:
        'If the audit user is a System Administrator, this is a defect in the check: please report it at ' +
        'https://github.com/cclabsnz/sf-audit-plugin/issues with the error above. The area this check covers is unassessed, not clean.',
      inconclusive: true,
      notAssessed: true,
    };
  }
  return {
    ...base,
    title: `${check.name}: check failed`,
    detail: `This check encountered an error and could not complete: ${msg}`,
    remediation: 'Review the error message and re-run the audit. The area this check covers is unassessed, not clean.',
    notAssessed: true,
  };
}

export class CheckEngine {
  constructor(
    private readonly checks: SecurityCheck[],
    private readonly ctx: AuditContext,
    private readonly scoringConfig?: ScoringConfig,
    private readonly waiverLoader?: WaiverLoader,
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
        findings.push(...result.findings.map((f) => ({
          ...f, checkId: check.id, complianceTags: tags, threats: withAttack(f, threatsFor(check.id, f.threats)),
        })));
        if (result.metrics) {
          metrics = { ...metrics, ...result.metrics };
        }
      } catch (err) {
        findings.push({ ...buildErrorFinding(check, err), threats: threatsFor(check.id) });
      }
    }

    // Waivers apply before correlation but do not remove findings from it: an accepted weakness
    // still forms attack paths with the others.
    const finalFindings = this.waiverLoader ? applyWaivers(findings, this.waiverLoader).findings : findings;
    const attackChains = new ChainEngine().correlate(finalFindings);
    return buildAuditResult(this.ctx, finalFindings, metrics, this.scoringConfig, attackChains);
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
