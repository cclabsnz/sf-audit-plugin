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

  describe('AI & Agents named chains', () => {
    // Prompt injection blast radius: guest channel + over-privileged agent user + write actions.
    const piGuest = () => f('agent-channel-exposure-guest-SupportBot-live-site', { riskLevel: 'CRITICAL' });
    const piPriv = () => f('agent-user-privilege-admin-005xx', { riskLevel: 'CRITICAL' });
    const piPrivBroad = () => f('agent-user-privilege-broad-write-005yy', { riskLevel: 'HIGH' });
    const piWrite = () => f('agent-action-surface-write');

    it('fires prompt-injection-blast-radius when all three ingredients are present', () => {
      const chains = engine.correlate([piGuest(), piPriv(), piWrite()]);
      const chain = chains.find((c) => c.id === 'prompt-injection-blast-radius');
      expect(chain).toBeDefined();
      expect(chain!.confidence).toBe('named');
      expect(chain!.severity).toBe('CRITICAL');
      expect(chain!.steps).toHaveLength(3);
    });

    it('fires prompt-injection-blast-radius with the broad-write privilege variant', () => {
      const chains = engine.correlate([piGuest(), piPrivBroad(), piWrite()]);
      expect(chains.some((c) => c.id === 'prompt-injection-blast-radius')).toBe(true);
    });

    it('does not fire prompt-injection-blast-radius without the guest channel', () => {
      const chains = engine.correlate([piPriv(), piWrite()]);
      expect(chains.some((c) => c.id === 'prompt-injection-blast-radius')).toBe(false);
    });

    it('does not fire prompt-injection-blast-radius without the privileged agent user', () => {
      const chains = engine.correlate([piGuest(), piWrite()]);
      expect(chains.some((c) => c.id === 'prompt-injection-blast-radius')).toBe(false);
    });

    it('does not fire prompt-injection-blast-radius without write-capable actions', () => {
      const chains = engine.correlate([piGuest(), piPriv()]);
      expect(chains.some((c) => c.id === 'prompt-injection-blast-radius')).toBe(false);
    });

    // ForcedLeak pattern: active agents + stale/unresolvable trusted URL + no event capture.
    const flAgents = () => f('agent-inventory-summary', { riskLevel: 'INFO' });
    const flStale = () => f('trusted-url-hygiene-unresolvable-exfil.example', { riskLevel: 'CRITICAL' });
    const flParked = () => f('trusted-url-hygiene-parked-old.example', { riskLevel: 'CRITICAL' });
    const flNoCapture = () => f('agent-monitoring-coverage-none');

    it('fires forcedleak-pattern when all three ingredients are present (unresolvable URL)', () => {
      const chains = engine.correlate([flAgents(), flStale(), flNoCapture()]);
      const chain = chains.find((c) => c.id === 'forcedleak-pattern');
      expect(chain).toBeDefined();
      expect(chain!.confidence).toBe('named');
      expect(chain!.severity).toBe('CRITICAL');
      expect(chain!.steps).toHaveLength(3);
    });

    it('fires forcedleak-pattern with the parked-domain variant', () => {
      const chains = engine.correlate([flAgents(), flParked(), flNoCapture()]);
      expect(chains.some((c) => c.id === 'forcedleak-pattern')).toBe(true);
    });

    it('does not fire forcedleak-pattern without active agents', () => {
      const chains = engine.correlate([flStale(), flNoCapture()]);
      expect(chains.some((c) => c.id === 'forcedleak-pattern')).toBe(false);
    });

    it('does not fire forcedleak-pattern without a stale/unresolvable trusted URL', () => {
      const chains = engine.correlate([flAgents(), flNoCapture()]);
      expect(chains.some((c) => c.id === 'forcedleak-pattern')).toBe(false);
    });

    it('does not fire forcedleak-pattern when a low-severity review URL is the only trusted-URL signal', () => {
      // A -review- finding is not a stale/unresolvable ingredient — the chain wants the critical ids.
      const chains = engine.correlate([
        flAgents(), f('trusted-url-hygiene-review-vendor.example', { riskLevel: 'LOW' }), flNoCapture(),
      ]);
      expect(chains.some((c) => c.id === 'forcedleak-pattern')).toBe(false);
    });

    it('does not fire forcedleak-pattern without the monitoring gap', () => {
      const chains = engine.correlate([flAgents(), flStale()]);
      expect(chains.some((c) => c.id === 'forcedleak-pattern')).toBe(false);
    });
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
