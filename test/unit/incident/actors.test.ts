import { describe, it, expect, beforeAll } from '@jest/globals';
import type { Wave } from '../../../src/incident/model.js';
import { generateScenario, ACTOR_IPS, PROBE_IP } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { findActors, blockOf } from '../../../src/incident/analyse/actors.js';
import { loadIpRanges } from '../../../src/incident/ipRanges.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('blockOf', () => {
  it('uses /24 for IPv4 and /64 for IPv6', () => {
    expect(blockOf('203.0.113.105')).toBe('203.0.113.0/24');
    expect(blockOf('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
    expect(blockOf('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(blockOf('2001:DB8::1')).toBe(blockOf('2001:db8::1'));
  });
});

describe('findActors', () => {
  it('finds the W3 scanner block as one steady outlier actor with scanner markers', async () => {
    const w3 = b.manifest.waves.find((w) => w.id === 'W3')!;
    const actors = await findActors(b, w3, loadIpRanges([{ name: 'cloud.txt', text: '203.0.113.0/24' }]));
    expect(actors).toHaveLength(1);
    const a = actors[0];
    expect(a.block).toBe('203.0.113.0/24');
    expect(a.ips.sort()).toEqual([...ACTOR_IPS].sort());
    expect(a.controllerCalls).toBe(4800);
    expect(a.steady).toBe(true);
    expect(a.markers).toContain('log4shell');
    expect(a.emptyUaShare).toBeGreaterThan(0.99);
    expect(a.hosting).toBe('cloud.txt');
    expect(a.sources).toEqual(['outlier']);
    expect(a.actionCounts['SelectableListDataProviderController.getItems']).toBe(198);
    expect(a.actionCounts['SiteLoginFormController.login']).toBe(40);
    expect(a.firstSeen.slice(11, 13)).toBe('04');
    expect(a.lastSeen.slice(11, 13)).toBe('11');
  });
  it('finds the W1 probe through the detector SourceIp even though it is not an outlier', async () => {
    const w1 = b.manifest.waves.find((w) => w.id === 'W1')!;
    const actors = await findActors(b, w1, null);
    expect(actors.map((a) => a.ips)).toEqual([[PROBE_IP]]);
    expect(actors[0].sources).toContain('detector-ip');
    expect(actors[0].hostingAssessed).toBe(false);
  });
});

describe('findActors robustness', () => {
  it('does not crash on rows with an empty TIMESTAMP_DERIVED', async () => {
    const guest = '005xx000000gstA';
    const wave: Wave = { id: 'W9', guestId15: guest, site: 's', days: ['2026-01-02'], eventIds: [] };
    const row = (ts: string) => ({ TIMESTAMP_DERIVED: ts, USER_ID: guest, CLIENT_IP: '10.9.9.9', USER_AGENT: '', URI: '/', ACTION_MESSAGE: '1$apex://SiteLoginFormController/ACTION$login=1' });
    const rows = [row(''), ...Array.from({ length: 150 }, (_, i) => row(`2026-01-02T0${i % 4}:00:00.000Z`))];
    const fake = {
      manifest: { waves: [wave], logs: [] },
      anomalies: [{ eventIdentifier: 'e1', sourceIp: ' 10.9.9.9 ' }],
      rows: async function* () { yield* rows; },
    } as unknown as Bundle;
    fake.manifest.waves[0].eventIds = ['e1'];
    const actors = await findActors(fake, wave, null);
    expect(actors).toHaveLength(1);
    expect(actors[0].firstSeen.startsWith('2026-01-02T00')).toBe(true);
    expect(actors[0].actionCounts['SiteLoginFormController.login']).toBe(151);
  });
});
