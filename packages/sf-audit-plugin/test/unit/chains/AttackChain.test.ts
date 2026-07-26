// test/unit/chains/AttackChain.test.ts
import type { AttackChain } from '../../../src/chains/AttackChain.js';

describe('AttackChain type', () => {
  it('constructs a well-formed chain object', () => {
    const chain: AttackChain = {
      id: 'unauth-bulk-exfil',
      title: 'Unauthenticated bulk exfiltration',
      severity: 'CRITICAL',
      confidence: 'named',
      narrative: 'Guest foothold leads to bulk read.',
      remediation: 'Lock down guest access.',
      steps: [{ findingId: 'guest-user-read-access', checkId: 'guest-user-access', capability: 'unauth-foothold' }],
    };
    expect(chain.steps[0].findingId).toBe('guest-user-read-access');
    expect(chain.confidence).toBe('named');
  });
});
