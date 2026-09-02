// test/unit/chains/namedChains.test.ts
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';
import { capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { Capability } from '../../../src/chains/Capability.js';

function f(id: string): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '' };
}
function present(findings: Finding[]): Set<Capability> {
  const s = new Set<Capability>();
  for (const fd of findings) for (const c of capabilitiesFor(fd).grants) s.add(c);
  return s;
}

describe('NAMED_CHAINS', () => {
  it('unauth-bulk-exfil fires for guest foothold + executable apex', () => {
    const findings = [f('guest-user-read-access'), f('guest-executable-apex-unprotected')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-user-read-access', 'guest-executable-apex-unprotected']),
    );
  });

  it('unauth-bulk-exfil fires for an API-enabled guest reaching a classic site surface', () => {
    const findings = [f('guest-api-access-enabled'), f('classic-sites-active')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-api-access-enabled', 'classic-sites-active']),
    );
  });

  it('standard-to-takeover fires for a foothold + delegated admin + login-as-any-user', () => {
    // guest-user-baseline supplies the unauth-foothold source; the login findings supply priv-esc.
    const findings = [f('guest-user-baseline'), f('login-access-policy-delegated-admins'), f('login-access-policy-login-as-enabled')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'standard-to-takeover')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(expect.arrayContaining(['login-access-policy-delegated-admins', 'login-access-policy-login-as-enabled']));
  });

  it('unauth-bulk-exfil does NOT fire without a foothold', () => {
    const findings = [f('guest-executable-apex-unprotected')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('active-guest-exfil fires when observed guest recon meets an exposed bulk-read surface', () => {
    const findings = [f('guest-traffic-anomaly-recon'), f('guest-object-exposure-public-owd')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-traffic-anomaly-recon', 'guest-object-exposure-public-owd']),
    );
  });

  it('active-guest-exfil does NOT fire on an exposed surface with no observed traffic', () => {
    const findings = [f('guest-object-exposure-public-owd')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('cred-theft-pivot fires for credential-theft + external-egress', () => {
    const findings = [f('hardcoded-credentials-found'), f('named-credentials-inventory')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'cred-theft-pivot')!;
    expect(chain.match(present(findings), findings)).not.toBeNull();
  });

  it('unauth-bulk-exfil fires for a guest with View All Users and a public external OWD on User', () => {
    const findings = [f('guest-user-visibility-view-all-users'), f('guest-user-visibility-owd')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-user-visibility-view-all-users', 'guest-user-visibility-owd']),
    );
  });

  it('unauth-bulk-exfil counts a guest Read grant on User as a step alongside a bulk path', () => {
    const findings = [f('guest-user-visibility-owd'), f('guest-user-visibility-object-read')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps!.map((s) => s.id)).toContain('guest-user-visibility-object-read');
  });

  it('active-guest-exfil fires when observed guest recon meets an enumerable user roster', () => {
    const findings = [f('guest-traffic-anomaly-recon'), f('guest-user-visibility-view-all-users')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-traffic-anomaly-recon', 'guest-user-visibility-view-all-users']),
    );
  });

  // The object-level Read grant needs a sharing path to return anyone else's record, so it is not a
  // confirmed exposure on its own and must not carry an "incident in progress" claim by itself.
  it('active-guest-exfil does NOT fire on recon plus an object-read grant alone', () => {
    const findings = [f('guest-traffic-anomaly-recon'), f('guest-user-visibility-object-read')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  // Named chains carry a floor of MEDIUM: they are correlations someone hand-modelled, so they must
  // outrank the emergent "potential path" output. MEDIUM is reserved for a chain that adds no new
  // exposure of its own — `undetected-compromise` reports that exposure already present would go
  // unobserved, which would be overstated as HIGH and is why this is not a CRITICAL/HIGH-only rule.
  it('every named chain has at least MEDIUM severity and a non-empty narrative', () => {
    for (const c of NAMED_CHAINS) {
      expect(['CRITICAL', 'HIGH', 'MEDIUM']).toContain(c.severity);
      expect(c.narrative.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
    }
  });
});
