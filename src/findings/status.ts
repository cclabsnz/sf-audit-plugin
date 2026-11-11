import type { AuditResult } from './AuditResult.js';
import type { Finding } from './Finding.js';

/** What a finding counts as on the report's page one; the HTML report, --summary and explain share it. */
export type FindingStatus = 'open' | 'info' | 'waived' | 'inconclusive' | 'passed';

export function findingStatus(f: Finding): FindingStatus {
  if (f.passed) return 'passed';
  if (f.inconclusive || f.notAssessed) return 'inconclusive';
  if (f.waived) return 'waived';
  return f.riskLevel === 'INFO' ? 'info' : 'open';
}

/** Open findings per severity: what the score and the executive report count (RULE-079). */
export function openCounts(result: AuditResult): Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', number> {
  const open = result.findings.filter((f) => findingStatus(f) === 'open');
  return {
    CRITICAL: open.filter((f) => f.riskLevel === 'CRITICAL').length,
    HIGH: open.filter((f) => f.riskLevel === 'HIGH').length,
    MEDIUM: open.filter((f) => f.riskLevel === 'MEDIUM').length,
    LOW: open.filter((f) => f.riskLevel === 'LOW').length,
  };
}
