// test/unit/chains/CapabilityRegistry.test.ts
import { CAPABILITY_REGISTRY, capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(id: string, extra: Partial<Finding> = {}): Finding {
  return { id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '', ...extra };
}

describe('CapabilityRegistry', () => {
  it('maps known guest finding to unauth-foothold + data-read', () => {
    expect(CAPABILITY_REGISTRY['guest-user-read-access'].grants).toEqual(
      expect.arrayContaining(['unauth-foothold', 'data-read']),
    );
  });

  it('capabilitiesFor returns registry grants for an active finding', () => {
    expect(capabilitiesFor(f('guest-user-read-access')).grants).toContain('unauth-foothold');
  });

  it('capabilitiesFor returns nothing for passed findings', () => {
    expect(capabilitiesFor(f('guest-user-read-access', { passed: true })).grants).toEqual([]);
  });

  it('capabilitiesFor returns nothing for inconclusive findings', () => {
    expect(capabilitiesFor(f('guest-user-read-access', { inconclusive: true })).grants).toEqual([]);
  });

  it('inline capabilities override the registry', () => {
    const finding = f('some-new-finding', { capabilities: { grants: ['code-exec'] } });
    expect(capabilitiesFor(finding).grants).toEqual(['code-exec']);
  });
});
