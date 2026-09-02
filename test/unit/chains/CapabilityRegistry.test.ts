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

  it('grants unauth-foothold + bulk read to API-enabled guests', () => {
    expect(CAPABILITY_REGISTRY['guest-api-access-enabled'].grants).toEqual(
      expect.arrayContaining(['unauth-foothold', 'data-read-bulk']),
    );
  });

  it('grants bulk-read to the mass data-export capability', () => {
    expect(capabilitiesFor(f('data-export-weekly-export')).grants).toContain('data-read-bulk');
  });

  it('grants priv-esc to login-as-any-user', () => {
    expect(capabilitiesFor(f('login-access-policy-login-as-enabled')).grants).toContain('priv-esc');
  });

  // guest-user-visibility: three paths to the same outcome, graded differently. The two that expose
  // every User record on their own are bulk reads; the object-level Read grant is not, because it
  // still needs a sharing path to return anyone else's record.
  it('grants unauth-foothold + bulk read to a guest holding View All Users', () => {
    expect(capabilitiesFor(f('guest-user-visibility-view-all-users')).grants).toEqual(
      expect.arrayContaining(['unauth-foothold', 'data-read-bulk']),
    );
  });

  it('grants unauth-foothold + bulk read to a public external OWD on User', () => {
    expect(capabilitiesFor(f('guest-user-visibility-owd')).grants).toEqual(
      expect.arrayContaining(['unauth-foothold', 'data-read-bulk']),
    );
  });

  it('grants read but NOT bulk read to a guest Read grant on the User object', () => {
    const grants = capabilitiesFor(f('guest-user-visibility-object-read')).grants;
    expect(grants).toEqual(expect.arrayContaining(['unauth-foothold', 'data-read']));
    expect(grants).not.toContain('data-read-bulk');
  });
});
