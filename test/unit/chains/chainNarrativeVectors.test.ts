import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';

/**
 * The guest chains describe a concrete request path, not just an abstract "exposure". That detail is
 * the difference between a client reading "guest exposure" as theoretical and understanding that an
 * unauthenticated HTTP request returns their data, so it is worth pinning:
 *
 *   - the endpoint and Aura action must stay spelled the same way in the chain narratives as in
 *     GuestObjectExposureCheck, which is where the reachability grading derives it from;
 *   - the narratives name the vector but must not carry a copy-pasteable exploit body, because they
 *     are rendered into a client-facing executive report that circulates beyond the security team.
 */

const ROOT = process.cwd();
const AURA_PATH = '/s/sfsites/aura';
const GRAPHQL_ACTION = 'RecordUiController/ACTION$executeGraphQL';

const narrativeOf = (id: string): string => {
  const chain = NAMED_CHAINS.find((c) => c.id === id);
  expect(chain).toBeDefined();
  return `${chain!.narrative} ${chain!.remediation}`;
};

describe('guest chain narratives name the actual request path', () => {
  it('unauth-bulk-exfil names the Aura endpoint and both read vectors', () => {
    const text = narrativeOf('unauth-bulk-exfil');
    expect(text).toContain(AURA_PATH);
    expect(text).toContain('aura.token=null');
    expect(text).toContain('executeGraphQL');
    expect(text).toContain('aura.ApexAction.execute');
    // The point a reader must not miss: authentication controls are not in the path at all.
    expect(text).toMatch(/MFA|login/i);
  });

  it('active-guest-exfil names the recon signature and where it is observed', () => {
    const text = narrativeOf('active-guest-exfil');
    expect(text).toContain(AURA_PATH);
    expect(text).toContain('totalCount');
    expect(text).toContain('AuraRequest');
  });

  it('uses the same endpoint and action spelling as the check that grades reachability', () => {
    const check = readFileSync(
      join(ROOT, 'src/checks/impl/GuestObjectExposureCheck.ts'), 'utf8',
    );
    // If the check's wording is ever revised, the chain narratives must be revised with it.
    expect(check).toContain(AURA_PATH);
    expect(check).toContain(GRAPHQL_ACTION);
    const chains = readFileSync(join(ROOT, 'src/chains/namedChains.ts'), 'utf8');
    expect(chains).toContain(AURA_PATH);
  });

  it('agent channels name the messaging host, not the Aura endpoint', () => {
    // Verified 2026-08 against the Messaging for In-App and Web API: agent conversations go to the
    // org's SCRT2 messaging host, and guest reachability comes from that API's unauthenticated
    // access-token flow keyed on orgId + esDeveloperName. They do NOT traverse /s/sfsites/aura.
    // Conflating the two would put a wrong endpoint in a client deliverable, so it is pinned.
    const text = narrativeOf('prompt-injection-blast-radius');
    expect(text).toContain('my.salesforce-scrt.com');
    expect(text).toContain('/iamessage/api/v2');
    expect(text).toContain('esDeveloperName');
    expect(text).not.toContain(AURA_PATH);
  });

  it('keeps the guest-data and agent-channel vectors distinct', () => {
    // The guest bulk-read chains must not claim the messaging host, and the agent chain must not
    // claim the Aura endpoint. One sentence copied between them would make both wrong.
    expect(narrativeOf('unauth-bulk-exfil')).not.toContain('salesforce-scrt.com');
    expect(narrativeOf('active-guest-exfil')).not.toContain('salesforce-scrt.com');
  });

  it('stops short of a copy-pasteable exploit in any narrative', () => {
    // Naming the endpoint is standard pentest reporting; shipping a working request body into a
    // client deliverable is a different decision, and this encodes that it was made deliberately.
    for (const chain of NAMED_CHAINS) {
      const text = `${chain.narrative} ${chain.remediation}`;
      expect(text).not.toMatch(/curl |POST \/|message=\{|aura\.context=/i);
    }
  });
});
