import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from './Finding.js';

/** Audit completed; nothing the caller asked to fail on. */
export const EXIT_OK = 0;
/** Findings at or above the --fail-on threshold. */
export const EXIT_FINDINGS = 1;
/** Audit ran, but checks could not gather evidence. Only when --fail-on-inconclusive is set. */
export const EXIT_INCONCLUSIVE = 3;

/**
 * Severity order, most severe first. INFO is deliberately absent: it is not a
 * severity a caller can gate on, it is the level carried by passing and
 * inconclusive findings.
 */
const ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export interface ExitOptions {
  failOn?: RiskLevel;
  failOnInconclusive?: boolean;
}

/**
 * Findings at or above `failOn`.
 *
 * Ranks are compared only after confirming the level is gateable. Testing
 * `ORDER.indexOf(level) <= threshold` alone treats INFO (index -1) as more severe
 * than CRITICAL, which made every passing check a violation.
 */
export function violationsFor(findings: Finding[], failOn: RiskLevel): Finding[] {
  const threshold = ORDER.indexOf(failOn);
  if (threshold < 0) return [];
  return findings.filter((f) => {
    if (f.passed === true || f.inconclusive === true) return false;
    const rank = ORDER.indexOf(f.riskLevel);
    return rank >= 0 && rank <= threshold;
  });
}

/**
 * The process exit code for a completed audit.
 *
 * A definite finding outranks unknown coverage: when both apply the caller gets
 * EXIT_FINDINGS, and the inconclusive count is still carried in the report body.
 */
export function resolveExitCode(findings: Finding[], opts: ExitOptions): number {
  if (opts.failOn !== undefined && violationsFor(findings, opts.failOn).length > 0) {
    return EXIT_FINDINGS;
  }
  if (opts.failOnInconclusive === true && findings.some((f) => f.inconclusive === true)) {
    return EXIT_INCONCLUSIVE;
  }
  return EXIT_OK;
}
