// test/unit/incident/realOrgPatterns.test.ts
// Regressions from the first real-org validation run: shapes the original synthetic scenario
// did not have (always-on proxies, shared egress, shared request ids, data-returning baseline reads).
import { describe, it, expect } from '@jest/globals';
import { analyseBundle } from '../../../src/incident/analyse/index.js';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { actorlessCustomReads, alwaysOnProxy, credentialStuffing, exfilFromOtherIps, realisticBaselineReads, selfRegisteredThrowaways, sharedEgressActor, sharedRequestIds, singleBaselineSpill, visitorReadsOnScanDay } from '../../fixtures/incident/variants.js';

// One analysis per bundle: analyseBundle re-hashes every file, which is slow on CI runners.
const analysed = new Map<string, ReturnType<typeof analyseBundle>>();
const wave = async (dir: string, id: string) => {
  if (!analysed.has(dir)) analysed.set(dir, analyseBundle(dir));
  return (await analysed.get(dir)!).waves.find((w) => w.wave.id === id)!;
};

describe('proxies are not attackers', () => {
  it('an always-on proxy busier on the wave days is not an actor; the scan block still is', async () => {
    const dir = await alwaysOnProxy();
    const w3 = await wave(dir, 'W3');
    expect(w3.actors.map((a) => a.block)).toEqual(['203.0.113.0/24']);
    expect(w3.classification).toBe('automated-scan');
    const w1 = await wave(dir, 'W1');
    expect(w1.actors.map((a) => a.block)).not.toContain('192.0.2.0/24');
  });
});

describe('shared egress', () => {
  it('logins from an actor IP used by many users are not access and not identity links', async () => {
    const w3 = await wave(await sharedEgressActor(), 'W3');
    expect(w3.outcomes.successfulLogins).toBe(0);
    expect(w3.outcomes.identityLinks).toEqual([]);
    expect(w3.actors[0].sharedEgressIps).toEqual(['203.0.113.100']);
    expect(w3.classification).toBe('automated-scan');
    expect(w3.limits.join(' ')).toMatch(/shared by many users/);
  });
});

describe('request ids shared across many rows are never joined', () => {
  it('a 1 MB row sharing a request id with 784 small rows is not reported as returned content', async () => {
    const w3 = await wave(await sharedRequestIds(), 'W3');
    expect(w3.responses.returnedContent.some((x) => x.size === 1023096)).toBe(false);
    expect(w3.responses.ambiguousCalls).toBe(198);
    expect(w3.result).toBe('not-assessed');
    expect(w3.limits.join(' ')).toMatch(/198 calls shared a request id/);
  });
});

describe('the empty size is learned per action', () => {
  it('data-returning baseline reads do not raise the getItems empty size above 1846', async () => {
    const w3 = await wave(await realisticBaselineReads(), 'W3');
    expect(w3.responses.emptySizeByAction['SelectableListDataProviderController.getItems']).toBe(1846);
    expect(w3.responses.returnedContent.map((x) => x.size).sort((a, c) => a - c)).toEqual([2185, 2185, 2185, 2701, 4442, 8488, 9385]);
  });
});

describe('ordinary visitors on the wave days', () => {
  it('their data-bearing replies are context, not the verdict; their empty lists teach the getItems empty size', async () => {
    const dir = await visitorReadsOnScanDay();
    const w3 = await wave(dir, 'W3');
    expect(w3.responses.emptySizeByAction['SelectableListDataProviderController.getItems']).toBe(1846);
    const byActor = w3.responses.returnedContent.filter((x) => x.actorId !== '');
    expect(byActor.map((x) => x.size).sort((a, c) => a - c)).toEqual([2185, 2185, 2185, 2701, 4442, 8488, 9385]);
    expect(w3.responses.returnedContent.filter((x) => x.actorId === '').length).toBe(50);
    expect(w3.result).toBe('content-returned');
    expect(w3.nextSteps.join(' ')).toMatch(/Replay the 7 data-access calls/);
    expect(w3.limits.join(' ')).toMatch(/50 replies to other guest traffic/);
  });
  it('a wave whose actor got only empty replies is not called content-returned because of visitors', async () => {
    const dir = await visitorReadsOnScanDay();
    const { rewriteLog } = await import('../../fixtures/incident/variants.js');
    const { D2 } = await import('../../fixtures/incident/generate.js');
    await rewriteLog(dir, 'Sites', D2, (r) => (['9385', '8488', '4442', '2701', '2185'].includes(r.RESPONSE_SIZE) ? { ...r, RESPONSE_SIZE: '1846' } : r));
    const w3 = await wave(dir, 'W3');
    // The visitors' getItems content is normal (the action recurs on baseline days), so it is
    // context; the actor got only empty replies and every read joined.
    expect(w3.result).toBe('no-evidence');
  });
});

describe('fallback empty size is disclosed', () => {
  it('says when calls were judged against the site-wide reference because their action had no empty size of its own', async () => {
    const w3 = await wave(await generateScenario(), 'W3');
    expect(w3.responses.emptySizeByAction['SelectableListDataProviderController.getItems']).toBeUndefined();
    expect(w3.responses.judgedAgainstFallback).toBe(198);
    expect(w3.limits.join(' ')).toMatch(/198 data-access calls were judged against the site-wide reference size of 1861 bytes/);
  });
});

describe('pre-merge review: adversarial cases', () => {
  it('C1a: failed logins never make an actor IP look shared; a success after stuffing is access', async () => {
    const w3 = await wave(await credentialStuffing(), 'W3');
    expect(w3.actors[0].sharedEgressIps).toEqual([]);
    expect(w3.outcomes.successfulLogins).toBe(1);
    expect(w3.result).toBe('access-gained');
  });
  it('C1b: self-registered throwaway users never make an actor IP look shared', async () => {
    const w3 = await wave(await selfRegisteredThrowaways(), 'W3');
    expect(w3.actors[0].sharedEgressIps).toEqual([]);
    expect(w3.result).toBe('access-gained');
  });
  it('C1c: successful logins from a genuinely shared actor IP block no-evidence', async () => {
    const dir = await sharedEgressActor();
    const { rewriteLog } = await import('../../fixtures/incident/variants.js');
    const { D2 } = await import('../../fixtures/incident/generate.js');
    await rewriteLog(dir, 'Sites', D2, (r) => (Number(r.RESPONSE_SIZE) > 1900 && Number(r.RESPONSE_SIZE) < 99999 ? { ...r, RESPONSE_SIZE: '1846' } : r));
    const w3 = await wave(dir, 'W3');
    expect(w3.outcomes.sharedEgressLogins).toBe(20);
    expect(w3.result).toBe('not-assessed');
    expect(w3.limits.join(' ')).toMatch(/20 successful logins from shared actor IPs could not be attributed/);
  });
  it('C2: replies under test cannot teach their own empty size', async () => {
    const w3 = await wave(await actorlessCustomReads(), 'W3');
    expect(w3.responses.emptySizeByAction['PortalService.fetchCases']).toBeUndefined();
    expect(w3.responses.returnedContent.length).toBe(600);
    expect(w3.result).toBe('content-returned');
    expect(w3.classification).not.toBe('organic');
  });
  it('C3: content returned to the attacker on other IPs, for an action unseen on baseline days, decides the result', async () => {
    const w3 = await wave(await exfilFromOtherIps(), 'W3');
    expect(w3.actors.map((a) => a.block)).toEqual(['203.0.113.0/24']);
    expect(w3.responses.returnedContent.filter((x) => x.actorId === '').length).toBe(5);
    expect(w3.result).toBe('content-returned');
  });
  it('C4: with one baseline day, a scan that spilled past midnight is still an actor', async () => {
    const r = await analyseBundle(await singleBaselineSpill());
    const w3 = r.waves.find((w) => w.wave.id === 'W3')!;
    expect(w3.actors.map((a) => a.block)).toContain('203.0.113.0/24');
    expect(r.withinBaseline).toBe(false);
  });
});
