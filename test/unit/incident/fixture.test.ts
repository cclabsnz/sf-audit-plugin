import { describe, it, expect } from '@jest/globals';
import { generateScenario, ACTOR_IPS, D2, GUEST_A } from '../../fixtures/incident/generate.js';
import { loadBundle } from '../../../src/incident/bundleIo.js';

describe('incident fixture scenario', () => {
  it('writes a bundle that passes integrity and carries the W3 actor rows', async () => {
    const b = await loadBundle(await generateScenario());
    expect(b.manifest.waves.map((w) => w.id)).toEqual(['W1', 'W2', 'W3']);
    let actorCalls = 0;
    for await (const r of b.rows('AuraRequest', D2)) if (ACTOR_IPS.includes(r.CLIENT_IP) && r.ACTION_MESSAGE) actorCalls++;
    expect(actorCalls).toBe(8 * 600);
    expect(b.manifest.guests.find((g) => g.id15 === GUEST_A)?.siteNames).toEqual(['Site A']);
  });
});
