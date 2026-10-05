import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, GUEST_A, D1, D2 } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { computeDayVolumes, assessSpikes } from '../../../src/incident/analyse/baseline.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('baseline', () => {
  it('counts controller calls separately from page loads', async () => {
    const v = await computeDayVolumes(b);
    const d = v.find((x) => x.guestId15 === GUEST_A && x.day === '2026-09-14')!;
    expect(d.controllerCalls).toBe(400);
    expect(d.pageLoads).toBe(600);
  });
  it('flags W3 as a spike and W1 as not a spike, never mixing in the detector sample', async () => {
    const v = await computeDayVolumes(b);
    const w3 = assessSpikes(b, v, b.manifest.waves.find((w) => w.id === 'W3')!, 5);
    expect(w3).toEqual([{ day: D2, controllerCalls: 5200, baselineMedian: 400, ratio: 13, isSpike: true, detectorSample: 7266 }]);
    const w1 = assessSpikes(b, v, b.manifest.waves.find((w) => w.id === 'W1')!, 5);
    expect(w1[0].day).toBe(D1);
    expect(w1[0].isSpike).toBe(false);
    expect(w1[0].ratio).toBeCloseTo(1.75);
  });
  it('reports a null ratio when there are no baseline days', async () => {
    const v = await computeDayVolumes(b);
    const lone = { id: 'WX', guestId15: 'none', site: 'x', days: [D2], eventIds: [] };
    expect(assessSpikes(b, v, lone, 5)[0]).toMatchObject({ baselineMedian: null, ratio: null, isSpike: false });
  });
});
