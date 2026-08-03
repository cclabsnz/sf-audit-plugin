import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '@cclabsnz/sf-core';
import { getCheckMeta } from '../findings/CheckMeta.js';

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export interface Roadmap {
  quick: Finding[];
  moderate: Finding[];
  project: Finding[];
}

/** Group active findings into effort tiers, risk-sorted within each. Unknown checkId → moderate. */
export function buildRoadmap(findings: Finding[]): Roadmap {
  const out: Roadmap = { quick: [], moderate: [], project: [] };
  for (const f of findings) {
    if (f.passed || f.inconclusive) continue;
    const effort = (f.checkId && getCheckMeta(f.checkId)?.effort) || 'moderate';
    out[effort].push(f);
  }
  const sort = (arr: Finding[]): Finding[] => arr.sort((a, b) => RANK[a.riskLevel] - RANK[b.riskLevel]);
  sort(out.quick); sort(out.moderate); sort(out.project);
  return out;
}
