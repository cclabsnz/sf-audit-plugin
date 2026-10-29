import type { Finding } from '../findings/Finding.js';
import type { AttackChain } from '../chains/AttackChain.js';
import { ATTACK_TACTIC_ORDER, ATTACK_TECHNIQUES, tacticRank } from '../threats/attack.js';

export interface AttackJourney {
  /** Every tactic of the pinned release, in matrix order, with the open findings that enable it. */
  tactics: Array<{ tactic: string; findings: Finding[] }>;
  /** Per chain (same order as passed in), the tactic positions its shown techniques reach, ascending. */
  chains: number[][];
}

const isOpen = (f: Finding): boolean => !f.passed && !f.inconclusive && !f.notAssessed && !f.waived;

/**
 * Where findings and chains sit on the ATT&CK matrix. A finding counts under every tactic of every
 * technique it carries; a chain step under the earliest tactic of the techniques it shows. Only
 * verified techniques count (RULE-107), and a step showing none adds nothing.
 */
export function buildAttackJourney(findings: readonly Finding[], chains: readonly AttackChain[]): AttackJourney {
  const tactics = ATTACK_TACTIC_ORDER.map((tactic) => ({ tactic, findings: [] as Finding[] }));
  for (const f of findings.filter(isOpen)) {
    const hit = new Set<number>();
    for (const id of f.threats?.attack ?? []) {
      for (const t of ATTACK_TECHNIQUES[id]?.tactics ?? []) hit.add(ATTACK_TACTIC_ORDER.indexOf(t));
    }
    for (const i of hit) if (i >= 0) tactics[i].findings.push(f);
  }
  const journeys = chains.map((c) => {
    const reached = new Set<number>();
    for (const s of c.steps) {
      const r = tacticRank(s.techniques);
      if (r !== undefined) reached.add(r);
    }
    return [...reached].sort((a, b) => a - b);
  });
  return { tactics, chains: journeys };
}
