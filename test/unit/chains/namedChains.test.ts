// test/unit/chains/namedChains.test.ts
import {
  NAMED_CHAINS, EXPOSED_SECRETS, EGRESS_PATHS, GUEST_EXPOSURE, UNAUTH_EXFIL_STEPS, LOW_TRUST_ENTRY, PORTAL_REACH,
} from '../../../src/chains/namedChains.js';
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

  // API access reaches no record on its own: secure guest record access leaves a guest nothing to
  // read without a guest sharing rule, guest-owned records, or Apex that bypasses sharing.
  it('unauth-bulk-exfil needs a step that reaches records, not API access to a site alone', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const apiOnly = [f('guest-api-access-enabled'), f('classic-sites-active')];
    expect(chain.match(present(apiOnly), apiOnly)).toBeNull();
    const shared = [...apiOnly, f('guest-user-sharing-exposure')];
    expect(chain.match(present(shared), shared)!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-api-access-enabled', 'classic-sites-active', 'guest-user-sharing-exposure']),
    );
  });

  it('standard-to-takeover fires for a foothold + delegated admin + login-as-any-user', () => {
    // Self-registration is the low-trust way in (RULE-072); the login findings supply the escalation.
    // A guest user merely existing (guest-user-baseline) is not an entry.
    const findings = [f('experience-cloud-site-self-registration'), f('login-access-policy-delegated-admins'), f('login-access-policy-login-as-enabled')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'standard-to-takeover')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(expect.arrayContaining(['login-access-policy-delegated-admins', 'login-access-policy-login-as-enabled']));
  });

  it('standard-to-takeover fires for an integration account with escalation permissions', () => {
    const findings = [f('experience-cloud-site-self-registration'), f('integration-least-privilege-escalation-permissions'), f('escalation-perms-found')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'standard-to-takeover')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toContain('integration-least-privilege-escalation-permissions');
  });

  it('insider-bulk-exfil fires with integration bulk-data permissions as the broad-read step', () => {
    const findings = [
      f('integration-least-privilege-data-permissions'),
      f('data-export-weekly-export'),
      f('event-monitoring-disabled'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'insider-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toContain('integration-least-privilege-data-permissions');
  });

  it('unauth-bulk-exfil does NOT fire without a foothold', () => {
    const findings = [f('guest-executable-apex-unprotected')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('active-guest-exfil fires when observed guest recon meets an exposed bulk-read surface', () => {
    const findings = [f('guest-traffic-anomaly-recon'), f('guest-object-exposure-guest-owned')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-traffic-anomaly-recon', 'guest-object-exposure-guest-owned']),
    );
  });

  // Records shared with guests are what a site publishes on purpose: reads, not the bulk surface.
  it('active-guest-exfil does not take records shared with guests as the bulk surface', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    for (const id of ['guest-object-exposure-public-owd', 'guest-object-exposure-guest-shared']) {
      const findings = [f('guest-traffic-anomaly-recon'), f(id)];
      expect({ id, fired: chain.match(present(findings), findings) !== null }).toEqual({ id, fired: false });
    }
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

  it('cred-theft-pivot does NOT fire on a debug trace beside egress paths', () => {
    const findings = [f('debug-log-active-traces'), f('named-credentials-inventory'), f('remote-sites-inventory')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'cred-theft-pivot')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('cred-theft-pivot does NOT fire when egress comes only from a finding outside its steps', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'cred-theft-pivot')!;
    const secrets = [f('hardcoded-credentials-found'), f('custom-labels-credential-value-match')];
    for (const outside of ['org-wide-email-spoofing-no-dkim', 'outbound-messages-session-id']) {
      const findings = [...secrets, f(outside)];
      expect({ outside, steps: chain.match(present(findings), findings) }).toEqual({ outside, steps: null });
    }
    // A Flow callout carrying a hardcoded secret is both the secret and the way out.
    const viaFlow = [f('hardcoded-credentials-found'), f('flow-http-callout-hardcoded-secret')];
    expect(chain.match(present(viaFlow), viaFlow)).not.toBeNull();
  });

  it('EXPOSED_SECRETS all grant credential-theft and EGRESS_PATHS all grant external-egress', () => {
    for (const id of EXPOSED_SECRETS) expect({ id, grants: capabilitiesFor(f(id)).grants.includes('credential-theft') }).toEqual({ id, grants: true });
    for (const id of EGRESS_PATHS) expect({ id, grants: capabilitiesFor(f(id)).grants.includes('external-egress') }).toEqual({ id, grants: true });
  });

  // A public external OWD on User reaches logged-in external users, not guests: it never joins the
  // unauthenticated chain, and a site's guest member visibility is the guest roster path instead.
  it('unauth-bulk-exfil fires for a guest with View All Users, without the User external OWD as a step', () => {
    const findings = [f('guest-user-visibility-view-all-users'), f('guest-user-read-access'), f('guest-user-visibility-owd')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-user-visibility-view-all-users', 'guest-user-read-access']),
    );
    expect(steps!.map((s) => s.id)).not.toContain('guest-user-visibility-owd');
  });

  // One rule for records shared with guests, whichever object and OWD: they are reach, and the
  // chain also needs a step that reads in bulk, writes or runs code.
  it('unauth-bulk-exfil takes records shared with guests as reach, never as the bulk step', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    for (const shared of ['guest-object-exposure-guest-shared', 'guest-object-exposure-public-owd', 'guest-user-sharing-exposure']) {
      const alone = [f(shared), f('guest-user-baseline'), f('guest-user-read-access')];
      expect({ shared, fired: chain.match(present(alone), alone) !== null }).toEqual({ shared, fired: false });
      const withBulk = [...alone, f('guest-api-access-enabled')];
      expect({ shared, steps: chain.match(present(withBulk), withBulk)?.map((s) => s.id) })
        .toEqual({ shared, steps: expect.arrayContaining([shared, 'guest-api-access-enabled']) });
    }
  });

  // It shows a live site's members, not business records: a step, never the record reach, so a
  // guest user existing beside it does not make a CRITICAL bulk-exfiltration chain.
  // A site's member list is no foothold into org data, so it opens no chain's entry gate.
  it('guest member visibility opens neither the unauthenticated nor the low-trust chains', () => {
    expect(GUEST_EXPOSURE).not.toContain('guest-site-options-member-visibility');
    expect(LOW_TRUST_ENTRY).not.toContain('guest-site-options-member-visibility');
    const takeover = NAMED_CHAINS.find((c) => c.id === 'standard-to-takeover')!;
    const findings = [f('guest-site-options-member-visibility'), f('escalation-perms-found')];
    expect(takeover.match(present(findings), findings)).toBeNull();
  });

  it('unauth-bulk-exfil does not fire on guest member visibility and a guest user alone', () => {
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const alone = [f('guest-site-options-member-visibility'), f('guest-user-baseline'), f('guest-api-access-enabled')];
    expect(chain.match(present(alone), alone)).toBeNull();
    const withReach = [...alone, f('guest-object-exposure-guest-shared')];
    expect(chain.match(present(withReach), withReach)!.map((s) => s.id)).toContain('guest-site-options-member-visibility');
  });

  it('the User external OWD is a low-trust entry and portal reach, not a guest exposure', () => {
    expect(GUEST_EXPOSURE).not.toContain('guest-user-visibility-owd');
    expect(UNAUTH_EXFIL_STEPS).not.toContain('guest-user-visibility-owd');
    expect(LOW_TRUST_ENTRY).toContain('guest-user-visibility-owd');
    expect(PORTAL_REACH).toContain('guest-user-visibility-owd');
  });

  // The guest OWD is Private on every object, User included, so the external OWD reaches no guest
  // record: a guest sharing rule supplies the reach, and guest API access the bulk path.
  it('unauth-bulk-exfil needs record reach beside the User external OWD and a bulk path', () => {
    const chain0 = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const owdOnly = [f('guest-user-visibility-owd'), f('guest-user-read-access'), f('guest-api-access-enabled')];
    expect(chain0.match(present(owdOnly), owdOnly)).toBeNull();
    const findings = [...owdOnly, f('guest-user-sharing-exposure')];
    const steps = chain0.match(present(findings), findings);
    expect(steps!.map((s) => s.id)).toEqual(expect.arrayContaining(['guest-user-sharing-exposure', 'guest-api-access-enabled']));
    expect(steps!.map((s) => s.id)).not.toContain('guest-user-visibility-owd');
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

  // Guest object Read reaches no record on its own, so it must not carry an "incident in progress"
  // claim by itself.
  it('active-guest-exfil does NOT fire on recon plus guest object Read alone', () => {
    const findings = [f('guest-traffic-anomaly-recon'), f('guest-user-read-access')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'active-guest-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('inbound-email-rce fires when unauthenticated email execution meets unshared/vulnerable code', () => {
    const findings = [
      f('inbound-email-handler-unauthenticated-execution'),
      f('apex-crud-fls-without-sharing'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'inbound-email-rce')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['inbound-email-handler-unauthenticated-execution', 'apex-crud-fls-without-sharing']),
    );
  });

  it('inbound-email-rce does NOT fire without the email handler entry point', () => {
    const findings = [f('apex-crud-fls-without-sharing')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'inbound-email-rce')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('platform-event-priv-esc fires when a guest foothold combines with event subscriber escalation', () => {
    const findings = [
      f('guest-user-baseline'),
      f('platform-event-subscriber-escalation'),
      f('users-modify-all-data'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'platform-event-priv-esc')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-user-baseline', 'platform-event-subscriber-escalation', 'users-modify-all-data']),
    );
  });

  it('platform-event-priv-esc does NOT fire without a foothold', () => {
    const findings = [
      f('platform-event-subscriber-escalation'),
      f('users-modify-all-data'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'platform-event-priv-esc')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  // Named chains carry a floor of MEDIUM: they are correlations someone hand-modelled, so they must
  // outrank the emergent "potential path" output. MEDIUM is reserved for a chain that adds no new
  // exposure of its own — `undetected-compromise` reports that exposure already present would go
  // unobserved, which would be overstated as HIGH and is why this is not a CRITICAL/HIGH-only rule.
  it('unauth-bulk-exfil does NOT fire on an email foothold plus internal-only weaknesses', () => {
    // The email handler opens the unauth-foothold gate; Data Cloud and restriction rules are
    // internal weaknesses. Together they describe no unauthenticated bulk-read path.
    const findings = [
      f('inbound-email-handler-unauthenticated-execution'),
      f('data-cloud-data-space-default-overshared'),
      f('restriction-rules-inactive'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('unauth-bulk-exfil carries internal weaknesses as evidence once guest steps meet the floor', () => {
    const findings = [
      f('guest-user-read-access'),
      f('guest-executable-apex-unprotected'),
      f('data-cloud-data-space-default-overshared'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps!.map((s) => s.id)).toContain('data-cloud-data-space-default-overshared');
  });

  it('unauth-bulk-exfil shows the email handler when it is what opened the gate', () => {
    const findings = [
      f('inbound-email-handler-unauthenticated-execution'),
      f('guest-executable-apex-unprotected'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps!.map((s) => s.id)).toContain('inbound-email-handler-unauthenticated-execution');
  });

  it('standard-to-takeover does NOT fire on an email foothold plus two internal escalation paths', () => {
    const findings = [
      f('inbound-email-handler-unauthenticated-execution'),
      f('delegated-administration-groups-active'),
      f('delegated-authentication-admin-assigned'),
    ];
    const chain = NAMED_CHAINS.find((c) => c.id === 'standard-to-takeover')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('every named chain has at least MEDIUM severity and a non-empty narrative', () => {
    for (const c of NAMED_CHAINS) {
      expect(['CRITICAL', 'HIGH', 'MEDIUM']).toContain(c.severity);
      expect(c.narrative.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
    }
  });
});
