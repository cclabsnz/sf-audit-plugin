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

  it('grants code-exec and priv-esc to escalation permissions on an integration account', () => {
    const grants = capabilitiesFor(f('integration-least-privilege-escalation-permissions')).grants;
    expect(grants).toEqual(expect.arrayContaining(['code-exec', 'priv-esc']));
  });

  it('grants bulk read to integration bulk-data permissions', () => {
    expect(capabilitiesFor(f('integration-least-privilege-data-permissions')).grants).toContain('data-read-bulk');
  });

  // An unused grant is by definition not being exercised, and a dormant account is a theft target
  // rather than an attacker capability. Granting for either would inflate chains with paths nobody
  // is on.
  it('grants nothing for unused write objects, dormancy, or the hygiene finding', () => {
    expect(capabilitiesFor(f('integration-least-privilege-unused-write-objects')).grants).toEqual([]);
    expect(capabilitiesFor(f('integration-least-privilege-dormant')).grants).toEqual([]);
    expect(capabilitiesFor(f('integration-least-privilege-hygiene')).grants).toEqual([]);
  });

  // Credentials in custom settings sit alongside the hardcoded-literal and custom-label paths that
  // already grant, so cred-theft-pivot sees all three places a secret hides rather than two.
  it('grants credential-theft to credentials held in custom settings', () => {
    expect(capabilitiesFor(f('custom-settings-credentials')).grants).toContain('credential-theft');
  });

  // The @RestResource analogue of portal-exposed-apex-without-sharing. Sharing and CRUD/FLS are
  // independent controls: skipping sharing gives unattended write, skipping CRUD/FLS does not.
  it('grants code-exec and write to Apex REST declared without sharing', () => {
    expect(capabilitiesFor(f('apex-rest-without-sharing')).grants).toEqual(
      expect.arrayContaining(['code-exec', 'data-read', 'data-write']),
    );
  });

  it('grants read but NOT write or code-exec to Apex merely missing CRUD/FLS checks', () => {
    const grants = capabilitiesFor(f('apex-crud-fls-missing')).grants;
    expect(grants).toContain('data-read');
    expect(grants).not.toContain('data-write');
    expect(grants).not.toContain('code-exec');
  });

  it('grants credential-theft and egress to an outbound message carrying a session ID', () => {
    expect(capabilitiesFor(f('outbound-messages-session-id')).grants).toEqual(
      expect.arrayContaining(['credential-theft', 'external-egress']),
    );
  });

  // Anonymous file access grants read and, on purpose, no foothold. unauth-foothold is a SOURCE
  // capability, so the emergent pass would pair a public Document with every high-impact sink in
  // the org and report "unauthenticated foothold -> bulk read" on adjacency alone. A file is not a
  // session: the guest findings grant a foothold because a guest user context can be pivoted from,
  // whereas these return the file and stop. Pinned because it reads like an omission.
  it('grants read but NOT a foothold to anonymously fetchable files', () => {
    const ids = [
      'public-content-public-documents', 'public-content-public-static-resources',
      'content-links-no-expiry', 'content-links-no-password',
    ];
    for (const id of ids) {
      const grants = capabilitiesFor(f(id)).grants;
      expect(grants).toContain('data-read');
      expect(grants).not.toContain('unauth-foothold');
    }
  });

  // Self-registration is how an attacker obtains the account the external-sharing grants assume.
  it('grants a low-trust authenticated entry point to self-registration', () => {
    expect(capabilitiesFor(f('experience-cloud-site-self-registration')).grants).toContain(
      'low-trust-authenticated',
    );
  });

  // Full scope is reach. Never-expiring and stale tokens are evidence about a token rather than
  // reach an attacker holds, so they stay chain steps and grant nothing here.
  it('grants bulk read to the Full OAuth scope, and nothing to token persistence or disuse', () => {
    expect(capabilitiesFor(f('connected-app-full-scope')).grants).toContain('data-read-bulk');
    expect(capabilitiesFor(f('connected-app-infinite-refresh-token')).grants).toEqual([]);
    expect(capabilitiesFor(f('oauth-token-stale')).grants).toEqual([]);
  });
});
