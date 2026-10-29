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

describe('named chain wording and step roles', () => {
  // Guest record access is always secured (Winter '21), so external sharing defaults reach logged-in
  // portal users, not guests: they must not be steps of the chain that needs no account.
  it('unauth-bulk-exfil does not count external sharing defaults as an unauthenticated step', () => {
    const chains = new ChainEngine().correlate([
      f('guest-object-exposure-public-owd'), f('sharing-model-external-read'), f('sharing-model-external-write'), f('guest-user-read-access'),
    ]);
    const c = chains.find((x) => x.id === 'unauth-bulk-exfil')!;
    expect(c.steps.map((s) => s.findingId)).not.toContain('sharing-model-external-read');
    expect(c.steps.map((s) => s.findingId)).not.toContain('sharing-model-external-write');
  });

  // The reach must come from a guest-side step: an internal user's bulk read says nothing about
  // what a visitor without an account can take.
  it('unauth-bulk-exfil does not borrow bulk read or write from internal users', () => {
    const guest = [f('guest-user-read-access'), f('guest-user-baseline')];
    expect(match('unauth-bulk-exfil', guest)).toBeNull();
    expect(match('unauth-bulk-exfil', [...guest, f('users-modify-all-data'), f('users-author-apex')])).toBeNull();
    expect(match('unauth-bulk-exfil', [...guest, f('guest-executable-apex-unprotected')])?.map((s) => s.id))
      .toContain('guest-executable-apex-unprotected');
  });

  // Nor may the potential-chain pass pair the guest foothold with those internal grants instead.
  it.each([
    [['users-modify-all-data', 'users-author-apex']],
    [['users-view-all-data']],
    [['portal-exposed-apex-without-sharing']],
  ])('no chain pairs a guest foothold with %j', (internal) => {
    const chains = new ChainEngine().correlate([f('guest-user-read-access'), f('guest-user-baseline'), ...internal.map((id) => f(id))]);
    const guestChains = chains.filter((c) => c.steps.some((s) => s.findingId === 'guest-user-read-access'));
    for (const c of guestChains) for (const id of internal) expect(c.steps.map((s) => s.findingId)).not.toContain(id);
  });

  // These flag any @AuraEnabled class or any Flow, which may be callable only by a logged-in user.
  it.each(['portal-exposed-apex-without-sharing', 'flows-autolaunched-without-sharing', 'flows-screen-without-sharing'])(
    'unauth-bulk-exfil neither fires on nor lists %s, which is not shown to be guest-reachable',
    (id) => {
      const guest = [f('guest-user-read-access'), f('guest-user-baseline')];
      expect(match('unauth-bulk-exfil', [...guest, f(id)])).toBeNull();
      const steps = match('unauth-bulk-exfil', [...guest, f('guest-executable-apex-unprotected'), f(id)])!;
      expect(steps.map((s) => s.id)).not.toContain(id);
    },
  );

  it('cred-theft-pivot is rated no higher than its pattern-matched secret', () => {
    expect(NAMED_CHAINS.find((c) => c.id === 'cred-theft-pivot')!.severity).toBe('HIGH');
  });

  it('self-registration-foothold tells one story: its break point is a finding and its remediation leads with it', () => {
    const def = NAMED_CHAINS.find((c) => c.id === 'self-registration-foothold')!;
    expect(def.narrative).not.toMatch(/not a finding/);
    expect(def.remediation).not.toMatch(/Decide which half/);
    expect(def.remediation.startsWith('Turn self-registration off')).toBe(true);
    expect(def.remediation).not.toMatch(/approval step/);
    expect(def.abuseCase.breakPointText).toBe('Turn off self-registration on the site.');
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
    // RULE-072: a real low-trust entry is required; a guest user merely existing is not one.
    const chains = new ChainEngine().correlate([
      f('experience-cloud-site-self-registration'),
      f('privileged-access-shadow-admins'),
    ]);
    expect(chains.map((c) => c.id)).toContain('standard-to-takeover');
  });
});

describe('oauth-standing-access', () => {
  const fullScope = f('connected-app-full-scope');
  const infinite = f('connected-app-infinite-refresh-token');
  const combined = f('connected-app-full-scope-infinite-token', { riskLevel: 'CRITICAL' });
  const unmatched = f('oauth-token-unmatched-app');
  const stale = f('oauth-token-stale');
  const ipBypass = f('connected-apps-bypass-ip');

  it('fires when standing reach meets a token nobody is reviewing', () => {
    const steps = match('oauth-standing-access', [fullScope, unmatched]);
    expect(steps?.map((s) => s.id)).toEqual(['connected-app-full-scope', 'oauth-token-unmatched-app']);
  });

  it('fires when standing reach meets removed IP containment', () => {
    const steps = match('oauth-standing-access', [combined, ipBypass]);
    expect(steps?.map((s) => s.id)).toEqual([
      'connected-app-full-scope-infinite-token', 'connected-apps-bypass-ip',
    ]);
  });

  // The whole point of the chain is the conjunction. Broad standing access that somebody is
  // watching and limiting is a posture finding, not a path, and the individual checks already
  // report it on its own terms.
  it('does not fire on standing reach alone, however severe', () => {
    expect(match('oauth-standing-access', [combined, fullScope, infinite])).toBeNull();
  });

  it('does not fire on unreviewed or uncontained tokens without standing reach', () => {
    expect(match('oauth-standing-access', [unmatched, stale, ipBypass])).toBeNull();
  });

  // A token exchange produces no OAuth login row, so a chain that fired only on observed activity
  // would never fire at all. Nothing in the gate depends on evidence of use.
  it('fires without any evidence the access has been exercised', () => {
    expect(match('oauth-standing-access', [fullScope, stale])).not.toBeNull();
  });

  it('names why login controls do not apply, since that is the counter-intuitive part', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'oauth-standing-access')!;
    const text = `${chain.narrative} ${chain.remediation}`;
    expect(text).toContain('refresh token is not a session');
    expect(text).toContain('LoginHistory');
    // Revocation is the only control that ends a standing token, so the remediation has to lead
    // with it rather than with scope tidying.
    expect(chain.remediation).toContain('Revoke');
  });
});

describe('self-registration-foothold', () => {
  const selfReg = f('experience-cloud-site-self-registration');
  const externalRead = f('sharing-model-external-read');
  const portalApex = f('portal-exposed-apex-without-sharing');
  const social = f('auth-providers-social');

  it('fires when self-registration meets an over-shared external model', () => {
    const steps = match('self-registration-foothold', [selfReg, externalRead]);
    expect(steps?.map((s) => s.id)).toEqual([
      'experience-cloud-site-self-registration', 'sharing-model-external-read',
    ]);
  });

  // Each half is unremarkable alone: self-registration is a supported feature, and an external OWD
  // assumes an account the attacker may never get. The conjunction is the whole finding.
  it('does not fire on self-registration alone', () => {
    expect(match('self-registration-foothold', [selfReg])).toBeNull();
  });

  it('does not fire on external sharing alone', () => {
    expect(match('self-registration-foothold', [externalRead, portalApex])).toBeNull();
  });

  // Social sign-on is a second door, not a substitute for the first.
  it('does not fire on social auth providers without self-registration', () => {
    expect(match('self-registration-foothold', [social, externalRead])).toBeNull();
  });

  it('includes social auth providers as evidence when self-registration is also present', () => {
    const ids = match('self-registration-foothold', [selfReg, externalRead, social])?.map((s) => s.id);
    expect(ids).toContain('auth-providers-social');
  });

  // A self-registered account is a Customer Community licence, which generally has no report
  // access, so report folders must not count as reach here however tempting the wording is.
  it('does not treat public report folders as portal-reachable', () => {
    expect(match('self-registration-foothold', [selfReg, f('report-folder-access-public')])).toBeNull();
  });
});

describe('session-id-egress', () => {
  const leak = f('outbound-messages-session-id');
  const cleartext = f('outbound-messages-cleartext');
  const noMonitoring = f('event-monitoring-disabled');

  it('fires when the session ID leaves over a cleartext endpoint', () => {
    const steps = match('session-id-egress', [leak, cleartext]);
    expect(steps?.map((s) => s.id)).toEqual([
      'outbound-messages-session-id', 'outbound-messages-cleartext',
    ]);
  });

  it('fires when nothing would record the replay', () => {
    expect(match('session-id-egress', [leak, noMonitoring])).not.toBeNull();
  });

  it('does not fire without the session ID actually leaving', () => {
    expect(match('session-id-egress', [cleartext, noMonitoring])).toBeNull();
  });

  // The credential leaving is the finding; the chain reports it as a path only when something also
  // means a replay would go unstopped or unseen. OutboundMessagesCheck reports the leak alone.
  it('does not fire on the leak alone', () => {
    expect(match('session-id-egress', [leak])).toBeNull();
  });

  it('names the mechanism and leads remediation with clearing the option', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'session-id-egress')!;
    expect(chain.narrative).toContain('outbound message');
    expect(chain.remediation).toContain('Send Session ID');
  });
});

describe('anonymous-file-exposure', () => {
  const publicDocs = f('public-content-public-documents');
  const staleLink = f('content-links-stale');
  const noClassification = f('data-classification-missing');
  const noMonitoring = f('event-monitoring-disabled');

  it('fires when an anonymous file surface meets an inability to say what left', () => {
    const steps = match('anonymous-file-exposure', [publicDocs, noClassification]);
    expect(steps?.map((s) => s.id)).toEqual([
      'public-content-public-documents', 'data-classification-missing',
    ]);
  });

  it('does not fire on an anonymous file surface alone', () => {
    expect(match('anonymous-file-exposure', [publicDocs, staleLink])).toBeNull();
  });

  it('does not fire on missing classification or monitoring without an exposed surface', () => {
    expect(match('anonymous-file-exposure', [noClassification, noMonitoring])).toBeNull();
  });

  // content-links-stale is a subset of content-links-no-expiry, so it counts as surface only.
  // Listing it on both sides would let one check satisfy the whole conjunction by itself.
  it('does not let stale links satisfy both halves of the conjunction', () => {
    expect(match('anonymous-file-exposure', [staleLink])).toBeNull();
  });

  // The chain claims less than the guest chains on purpose: a file is not a pivot.
  it('does not claim a pivot into org data', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'anonymous-file-exposure')!;
    expect(chain.narrative).toContain('does not assert a pivot');
  });
});

describe('xss-to-privileged-session', () => {
  const vector = f('visualforce-xss-escape-false');
  const jsVector = f('visualforce-xss-js-merge-field');
  const weakened = f('session-hardening-risks');
  const insecureCsp = f('csp-trusted-sites-insecure');
  const target = f('users-super-admin-combo');

  it('fires only with a vector, weakened browser protection and a privileged target', () => {
    const steps = match('xss-to-privileged-session', [vector, weakened, target]);
    expect(steps?.map((s) => s.id)).toEqual([
      'visualforce-xss-escape-false', 'session-hardening-risks', 'users-super-admin-combo',
    ]);
  });

  it('does not fire without a privileged session worth stealing', () => {
    expect(match('xss-to-privileged-session', [vector, weakened])).toBeNull();
  });

  it('does not fire when the browser-side protections are intact', () => {
    expect(match('xss-to-privileged-session', [vector, target])).toBeNull();
  });

  it('does not fire without an XSS pattern in the markup', () => {
    expect(match('xss-to-privileged-session', [weakened, insecureCsp, target])).toBeNull();
  });

  it('accepts the unencoded-merge-field vectors, not only escape="false"', () => {
    expect(match('xss-to-privileged-session', [jsVector, insecureCsp, target])).not.toBeNull();
  });

  // experience-csp-verify asks the operator to confirm a setting rather than reporting a weakness.
  // Counting an advisory as a confirmed gap would inflate the chain.
  it('does not treat the Experience Cloud CSP advisory as a confirmed weakness', () => {
    expect(match('xss-to-privileged-session', [vector, f('experience-csp-verify'), target])).toBeNull();
  });

  // A markup scan cannot show whether an attacker controls the rendered value, and a client-facing
  // narrative that implied otherwise would be asserting an exploit it has not demonstrated.
  it('states plainly that exploitability is not established', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'xss-to-privileged-session')!;
    expect(chain.narrative).toContain('does not claim');
    expect(chain.narrative).toContain('false positive');
  });
});
