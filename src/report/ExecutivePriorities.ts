import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '../findings/RiskLevel.js';

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/**
 * Select the top-N findings to surface as executive priorities.
 * Order: severity, then findings that participate in an attack chain, then title.
 * Excludes passed and inconclusive findings.
 */
export function selectPriorities(findings: Finding[], chainFindingIds: Set<string>, topN: number): Finding[] {
  return findings
    .filter((f) => !f.passed && !f.inconclusive)
    .slice()
    .sort((a, b) => {
      if (RANK[a.riskLevel] !== RANK[b.riskLevel]) return RANK[a.riskLevel] - RANK[b.riskLevel];
      const ac = chainFindingIds.has(a.id) ? 0 : 1;
      const bc = chainFindingIds.has(b.id) ? 0 : 1;
      if (ac !== bc) return ac - bc;
      return a.title.localeCompare(b.title);
    })
    .slice(0, topN);
}
