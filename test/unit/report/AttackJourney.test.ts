import { buildAttackJourney } from '../../../src/report/AttackJourney.js';
import { ATTACK_TACTIC_ORDER } from '../../../src/threats/attack.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';

const f = (id: string, attack: string[], extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id, category: 'C', riskLevel: 'HIGH', title: id, detail: 'd', remediation: 'r', threats: { attack }, ...extra,
});
const at = (tactic: string): number => ATTACK_TACTIC_ORDER.indexOf(tactic);

describe('buildAttackJourney', () => {
  it('counts each open finding under every tactic of its techniques, and skips closed ones', () => {
    const j = buildAttackJourney([
      f('a', ['T1190']),
      f('b', ['T1078.004']),
      f('c', ['T1190'], { passed: true }),
      f('d', ['T1190'], { waived: true }),
    ], []);
    expect(j.tactics.map((t) => t.tactic)).toEqual([...ATTACK_TACTIC_ORDER]);
    expect(j.tactics[at('initial-access')].findings.map((x) => x.id)).toEqual(['a', 'b']);
    // T1078.004 sits in four tactics; it counts once in each.
    for (const t of ['stealth', 'persistence', 'privilege-escalation']) {
      expect({ t, ids: j.tactics[at(t)].findings.map((x) => x.id) }).toEqual({ t, ids: ['b'] });
    }
  });

  it('places each chain step at the earliest tactic of the techniques it shows, in order', () => {
    const chain: AttackChain = {
      id: 'c', title: 'c', severity: 'CRITICAL', confidence: 'named', narrative: 'n', remediation: 'r',
      steps: [
        { findingId: 'x', capability: 'code-exec', techniques: ['T1059.009'] },
        { findingId: 'y', capability: 'unauth-foothold', techniques: ['T1190'] },
        { findingId: 'z', capability: 'data-read' },
      ],
    };
    expect(buildAttackJourney([], [chain]).chains).toEqual([[at('initial-access'), at('execution')]]);
  });
});
