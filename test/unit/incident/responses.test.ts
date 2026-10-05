import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import type { Wave } from '../../../src/incident/model.js';
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
    expect(r.unmatchedCalls).toBe(0);
  });
  it('reports nothing returned for W1, whose getItems replies are all empty-sized', async () => {
    const w1 = b.manifest.waves.find((w) => w.id === 'W1')!;
    const r = await analyseResponses(b, w1, await findActors(b, w1, null));
    expect(r.dataAccessCalls).toBe(20);
    expect(r.returnedContent).toEqual([]);
  });
  it('counts an actor call whose REQUEST_ID is absent from Sites as unmatched and never flags it', async () => {
    const aura = [
      { CLIENT_IP: '203.0.113.9', USER_ID: '005xx000000gstA', USER_ID_DERIVED: '', ACTION_MESSAGE: 'aura://ApexActionController/ACTION$execute(Foo.getItems)', REQUEST_ID: 'r1', TIMESTAMP_DERIVED: '2026-01-01T00:00:01Z' },
      { CLIENT_IP: '203.0.113.9', USER_ID: '005xx000000gstA', USER_ID_DERIVED: '', ACTION_MESSAGE: 'aura://ApexActionController/ACTION$execute(Foo.getItems)', REQUEST_ID: ' missing ', TIMESTAMP_DERIVED: '2026-01-01T00:00:02Z' },
    ];
    const sites = [{ REQUEST_ID: 'r1', RESPONSE_SIZE: '1846' }];
    const stub = { rows: (type: string) => (async function* () { yield* (type === 'Sites' ? sites : aura); })() } as unknown as Bundle;
    const wave = { id: 'WX', guestId15: '005xx000000gstA', site: 's', days: ['2026-01-01'], eventIds: [] } as Wave;
    const r = await analyseResponses(stub, wave, [{ ips: ['203.0.113.9'] }] as never);
    expect(r.dataAccessCalls).toBe(2);
    expect(r.joined).toBe(1);
    expect(r.unmatchedCalls).toBe(1);
    expect(r.returnedContent).toEqual([]);
  });
});
