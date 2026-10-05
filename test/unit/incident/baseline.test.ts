import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, GUEST_A, D1, D2 } from '../../fixtures/incident/generate.js';
import type { Wave } from '../../../src/incident/model.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { computeDayVolumes, assessSpikes, type DayVolume } from '../../../src/incident/analyse/baseline.js';

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

describe('baseline with a zero or missing median', () => {
  const G = '005xx000000gstZ';
  const wave: Wave = { id: 'WZ', guestId15: G, site: 'x', days: ['2026-09-20'], eventIds: [] };
  const logs = ['2026-09-10', '2026-09-11', '2026-09-20'].map((day) => ({ type: 'AuraRequest', day, status: 'collected', guestRowsByUser: {} }));
  const fake = (extraLogs: unknown[] = []) => ({
    manifest: { waves: [wave], logs: [...logs, ...extraLogs] },
    anomalies: [],
    rows: async function* () { /* no rows */ },
  }) as unknown as Bundle;
  const vol = (day: string, controllerCalls: number, pageLoads: number): DayVolume => ({ day, guestId15: G, controllerCalls, pageLoads, corroboration: {} });
  const pageOnly = [vol('2026-09-10', 0, 30), vol('2026-09-11', 0, 40)];

  it('treats a zero median with 150 wave-day calls as a spike and leaves the ratio null', () => {
    const r = assessSpikes(fake(), [...pageOnly, vol('2026-09-20', 150, 0)], wave, 5);
    expect(r[0]).toMatchObject({ baselineMedian: 0, ratio: null, isSpike: true });
  });
  it('does not treat 50 wave-day calls as a spike against a zero median', () => {
    const r = assessSpikes(fake(), [...pageOnly, vol('2026-09-20', 50, 0)], wave, 5);
    expect(r[0]).toMatchObject({ baselineMedian: 0, ratio: null, isSpike: false });
  });
  it('does not count a day with only corroboration rows as a baseline day', async () => {
    const uri = { type: 'URI', day: '2026-09-10', status: 'collected', guestRowsByUser: { [G]: 7 } };
    const b2 = { ...fake([uri]), manifest: { waves: [wave], logs: [{ type: 'AuraRequest', day: '2026-09-10', status: 'collected', guestRowsByUser: {} }, { type: 'AuraRequest', day: '2026-09-20', status: 'collected', guestRowsByUser: {} }, uri] } } as unknown as Bundle;
    const v = await computeDayVolumes(b2);
    expect(v.find((x) => x.day === '2026-09-10')?.corroboration).toEqual({ URI: 7 });
    const r = assessSpikes(b2, [...v, vol('2026-09-20', 150, 0)], wave, 5);
    expect(r[0]).toMatchObject({ baselineMedian: null, ratio: null, isSpike: false });
  });
});
