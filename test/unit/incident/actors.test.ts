import { describe, it, expect, beforeAll } from '@jest/globals';
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
