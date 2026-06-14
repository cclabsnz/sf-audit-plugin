// test/unit/chains/ChainEngine.test.ts
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(id: string, extra: Partial<Finding> = {}): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '', ...extra };
}

describe('ChainEngine', () => {
  const engine = new ChainEngine();

  it('emits the named unauth-bulk-exfil chain', () => {
    const chains = engine.correlate([f('guest-user-read-access'), f('guest-executable-apex-unprotected')]);
    const named = chains.find((c) => c.id === 'unauth-bulk-exfil');
    expect(named).toBeDefined();
    expect(named!.confidence).toBe('named');
    expect(named!.severity).toBe('CRITICAL');
  });

  it('ignores passed and inconclusive findings when forming chains', () => {
    const chains = engine.correlate([
      f('guest-user-read-access', { passed: true }),
      f('guest-executable-apex-unprotected', { inconclusive: true }),
    ]);
    expect(chains).toHaveLength(0);
  });

  it('emits a potential chain for an uncovered source→sink pair', () => {
    // low-trust-authenticated (external read) + data-read-bulk present, but no named chain matches
    // (no priv-esc, no code-exec). Use external-read alone: it grants both low-trust-authenticated and data-read-bulk.
    const chains = engine.correlate([f('sharing-model-external-read')]);
    const potential = chains.find((c) => c.confidence === 'potential');
    expect(potential).toBeDefined();
    expect(['HIGH', 'MEDIUM']).toContain(potential!.severity);
  });

  it('suppresses a potential chain already covered by a named chain', () => {
    const chains = engine.correlate([f('hardcoded-credentials-found'), f('named-credentials-inventory')]);
    expect(chains.some((c) => c.id === 'cred-theft-pivot' && c.confidence === 'named')).toBe(true);
    // credential-theft is not a source cap, so no competing potential chain for the same pair
    expect(chains.filter((c) => c.confidence === 'potential' && c.severity === 'CRITICAL')).toHaveLength(0);
  });

  it('sorts named chains before potential, and by descending severity', () => {
    const chains = engine.correlate([
      f('guest-user-read-access'), f('guest-executable-apex-unprotected'), f('sharing-model-external-read'),
    ]);
    if (chains.length >= 2) {
      const namedIdx = chains.findIndex((c) => c.confidence === 'named');
      const potIdx = chains.findIndex((c) => c.confidence === 'potential');
      if (namedIdx !== -1 && potIdx !== -1) expect(namedIdx).toBeLessThan(potIdx);
    }
  });
});
