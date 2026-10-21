import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '@cclabsnz/sf-core';
import { getCheckMeta } from '../findings/CheckMeta.js';

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export interface Roadmap {
  quick: Finding[];
  moderate: Finding[];
  project: Finding[];
}

/**
 * Group the findings that ask for a change into effort tiers, risk-sorted within each. Unknown
 * checkId → moderate. INFO findings (inventories, advisories) and not-assessed ones (a check that
 * failed or saw nothing) ask for no change, so they stay in the appendix and the coverage line.
 */
export function buildRoadmap(findings: Finding[]): Roadmap {
  const out: Roadmap = { quick: [], moderate: [], project: [] };
  for (const f of findings) {
    if (f.passed || f.inconclusive || f.waived || f.notAssessed || f.riskLevel === 'INFO') continue;
    const effort = (f.checkId && getCheckMeta(f.checkId)?.effort) || 'moderate';
    out[effort].push(f);
  }
  const sort = (arr: Finding[]): Finding[] => arr.sort((a, b) => RANK[a.riskLevel] - RANK[b.riskLevel]);
  sort(out.quick); sort(out.moderate); sort(out.project);
  return out;
}
