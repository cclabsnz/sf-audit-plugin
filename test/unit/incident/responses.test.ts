import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { findActors } from '../../../src/incident/analyse/actors.js';
import { analyseResponses } from '../../../src/incident/analyse/responses.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('analyseResponses', () => {
  it('finds exactly the 7 non-empty getItems replies, without duplicate or blank request ids inflating anything', async () => {
    const w3 = b.manifest.waves.find((w) => w.id === 'W3')!;
    const r = await analyseResponses(b, w3, await findActors(b, w3, null));
    // Samples are actor auth + data-access calls only: 191 getItems at 1846, 40 logins at 1861,
    // 7 large getItems. Rich-text calls (1856) are plumbing and excluded, so the mode is 1846.
    expect(r.emptySize).toBe(1846);
    expect(r.dataAccessCalls).toBe(198);
    expect(r.joined).toBe(r.dataAccessCalls + 40); // data-access + auth calls, each counted once
    expect(r.returnedContent.map((x) => x.size).sort((a, c) => a - c)).toEqual([2185, 2185, 2185, 2701, 4442, 8488, 9385]);
    expect(r.returnedContent.every((x) => x.actions.some((a) => a.endsWith('.getItems')))).toBe(true);
    expect(r.blankRequestIdsDropped).toBe(5);
  });
  it('reports nothing returned for W1, whose getItems replies are all empty-sized', async () => {
    const w1 = b.manifest.waves.find((w) => w.id === 'W1')!;
    const r = await analyseResponses(b, w1, await findActors(b, w1, null));
    expect(r.dataAccessCalls).toBe(20);
    expect(r.returnedContent).toEqual([]);
  });
});
