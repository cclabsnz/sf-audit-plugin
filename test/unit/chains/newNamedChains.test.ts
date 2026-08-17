import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import { capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { Capability } from '../../../src/chains/Capability.js';

function f(id: string, extra: Partial<Finding> = {}): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '', ...extra };
}

/** Run one named chain definition directly, deriving `present` the way ChainEngine does. */
function match(chainId: string, findings: Finding[]): Finding[] | null {
  const def = NAMED_CHAINS.find((c) => c.id === chainId);
  if (!def) throw new Error(`no such chain: ${chainId}`);
  const present = new Set<Capability>();
  for (const finding of findings) for (const c of capabilitiesFor(finding).grants) present.add(c);
  return def.match(present, findings);
}

describe('sandbox-pii-exposure', () => {
  it('fires when unmasked sandbox PII meets a weak control', () => {
    const steps = match('sandbox-pii-exposure', [
      f('sandbox-data-masking-pii-present'),
      f('internal-user-mfa-gaps'),
    ]);
    expect(steps?.map((s) => s.id)).toEqual(['sandbox-data-masking-pii-present', 'internal-user-mfa-gaps']);
  });

  it('does not fire on unmasked PII alone', () => {
    expect(match('sandbox-pii-exposure', [f('sandbox-data-masking-pii-present')])).toBeNull();
  });

  it('does not fire on weak controls without the PII', () => {
    expect(match('sandbox-pii-exposure', [f('internal-user-mfa-gaps')])).toBeNull();
  });
});

describe('insider-bulk-exfil', () => {
  const broad = f('public-group-sharing-exposure');
  const egress = f('data-export-weekly-export');
  const blind = f('event-monitoring-disabled');

  it('fires only with broad read, bulk egress and a monitoring blind spot', () => {
    const steps = match('insider-bulk-exfil', [broad, egress, blind]);
    expect(steps?.map((s) => s.id).sort()).toEqual(
      ['data-export-weekly-export', 'event-monitoring-disabled', 'public-group-sharing-exposure'],
    );
  });

  it('does not fire when the org is monitored', () => {
    expect(match('insider-bulk-exfil', [broad, egress])).toBeNull();
  });

  it('does not fire without a bulk-egress path', () => {
    expect(match('insider-bulk-exfil', [broad, blind])).toBeNull();
  });

  it('does not fire without broad internal readability', () => {
    expect(match('insider-bulk-exfil', [egress, blind])).toBeNull();
  });
});

describe('undetected-compromise', () => {
  it('fires when a real capability meets two or more detection gaps', () => {
    const steps = match('undetected-compromise', [
      f('guest-user-read-access'), // grants unauth-foothold
      f('threat-detection-inactive'),
      f('siem-integration-not-detected'),
    ]);
    expect(steps?.map((s) => s.id)).toContain('guest-user-read-access');
    expect(steps?.map((s) => s.id)).toContain('threat-detection-inactive');
  });

  it('does not fire on a single detection gap', () => {
    expect(match('undetected-compromise', [
      f('guest-user-read-access'),
      f('threat-detection-inactive'),
    ])).toBeNull();
  });

  it('does not fire when no exploitable capability is present', () => {
    expect(match('undetected-compromise', [
      f('threat-detection-inactive'),
      f('siem-integration-not-detected'),
    ])).toBeNull();
  });

  it('ignores passed and inconclusive findings via the engine', () => {
    const chains = new ChainEngine().correlate([
      f('guest-user-read-access', { passed: true }),
      f('threat-detection-inactive'),
      f('siem-integration-not-detected'),
    ]);
    expect(chains.map((c) => c.id)).not.toContain('undetected-compromise');
  });
});

describe('newly modelled capabilities', () => {
  it.each([
    ['separation-of-duties-self-escalation', 'org-takeover'],
    ['separation-of-duties-code-and-data', 'code-exec'],
    ['separation-of-duties-external-exfil-channel', 'external-egress'],
    ['privileged-access-shadow-admins', 'org-takeover'],
    ['flows-autolaunched-without-sharing', 'data-write'],
    ['flows-screen-without-sharing', 'code-exec'],
    ['public-group-sharing-exposure', 'data-read-bulk'],
    ['report-folder-access-public', 'data-read'],
    ['guest-record-access-policy-not-enforced', 'unauth-foothold'],
    ['encryption-coverage-unencrypted-sensitive', 'data-read'],
    ['sandbox-data-masking-pii-present', 'data-read'],
  ])('%s grants %s', (id, cap) => {
    expect(capabilitiesFor(f(id)).grants).toContain(cap);
  });

  it('a screen flow does not grant the unattended write an autolaunched flow does', () => {
    expect(capabilitiesFor(f('flows-screen-without-sharing')).grants).not.toContain('data-write');
  });

  it('shadow admins now reach a named takeover chain that they previously could not', () => {
    const chains = new ChainEngine().correlate([
      f('guest-user-baseline'),
      f('privileged-access-shadow-admins'),
    ]);
    expect(chains.map((c) => c.id)).toContain('standard-to-takeover');
  });
});
