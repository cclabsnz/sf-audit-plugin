import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, PROBE_IP, LINKED_USER } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { findActors } from '../../../src/incident/analyse/actors.js';
import { computeOutcomes } from '../../../src/incident/analyse/outcomes.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('computeOutcomes', () => {
  it('W3: no logins, and no self-registrations inside the actor window', async () => {
    const w3 = b.manifest.waves.find((w) => w.id === 'W3')!;
    const o = computeOutcomes(b, w3, await findActors(b, w3, null));
    expect(o).toMatchObject({ successfulLogins: 0, failedLogins: 0, selfRegistrationsInActorWindow: [], identityLinks: [] });
  });
  it('W1: links the probe IP to the user it later logged in as, created by a guest', async () => {
    const w1 = b.manifest.waves.find((w) => w.id === 'W1')!;
    const o = computeOutcomes(b, w1, await findActors(b, w1, null));
    expect(o.successfulLogins).toBe(1);
    expect(o.identityLinks).toEqual([{ ip: PROBE_IP, userId15: LINKED_USER, userName: 'Test Tester', email: 'test.tester@example.com', userCreatedDate: '2026-07-05T23:49:41Z', createdByGuest: 'Site A Guest User', loginTime: '2026-07-05T23:58:33Z' }]);
  });
});

describe('computeOutcomes self-registrations', () => {
  it('lists a self-registration inside the actor window but never counts it as access', async () => {
    const w1 = b.manifest.waves.find((w) => w.id === 'W1')!;
    const actors = await findActors(b, w1, null);
    const guestName = b.manifest.guests.find((g) => g.id15 === w1.guestId15)!.name;
    const at = actors[0].firstSeen;
    const reg = { createdDate: at, createdBy: guestName, section: null, action: 'x', display: 'Created new Customer User Someone' };
    const o = computeOutcomes({ ...b, audit: [reg], followUp: { ...b.followUp, logins: [] } } as Bundle, w1, actors);
    expect(o.selfRegistrationsInActorWindow).toEqual([reg]);
    expect(o.successfulLogins).toBe(0);
  });
});
