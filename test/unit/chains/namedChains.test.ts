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

  it('every named chain has a CRITICAL or HIGH severity and non-empty narrative', () => {
    for (const c of NAMED_CHAINS) {
      expect(['CRITICAL', 'HIGH']).toContain(c.severity);
      expect(c.narrative.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
    }
  });
});
