// test/unit/incident/acceptance.test.ts
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, GUEST_A, SITE_A, SITE_B } from '../../fixtures/incident/generate.js';
import { analyseBundle, FORBIDDEN_WORDS, type IncidentResult } from '../../../src/incident/analyse/index.js';

let r: IncidentResult;
beforeAll(async () => { r = await analyseBundle(await generateScenario()); });

describe('incident analysis acceptance (spec §1 scenario)', () => {
  it('W3: unattributed automated scan that returned content, no access gained', () => {
    const w3 = r.waves.find((w) => w.wave.id === 'W3')!;
    expect(w3.spikes[0].isSpike).toBe(true);
    expect(w3.actors).toHaveLength(1);
    expect(w3.actors[0].block).toBe('203.0.113.0/24');
    expect(w3.outcomes.successfulLogins).toBe(0);
    expect(w3.outcomes.selfRegistrationsInActorWindow).toEqual([]);
    expect(w3.responses.returnedContent).toHaveLength(7);
    expect(w3.classification).toBe('automated-scan');
    expect(w3.result).toBe('content-returned');
    expect(w3.asymmetries).toEqual([expect.objectContaining({ site: SITE_A, comparedSite: SITE_B })]);
  });
  it('W1 and W2: consistent with internal testing, linked through the later login', () => {
    for (const id of ['W1', 'W2']) {
      const w = r.waves.find((x) => x.wave.id === id)!;
      expect(w.classification).toBe('internal-testing');
      expect(w.result).toBe('access-gained');
      expect(w.outcomes.identityLinks).toHaveLength(1);
    }
  });
  it('states the Query All Files limit and the missing hosting assessment', () => {
    const all = r.waves.flatMap((w) => w.limits).join(' ');
    expect(all).toMatch(/Query All Files/);
    expect(all).toMatch(/Hosting provider not assessed/);
  });
  it('never uses the words attack or breach in generated text', () => {
    const text = r.waves.flatMap((w) => [...w.limits, ...w.nextSteps]).join(' ');
    expect(FORBIDDEN_WORDS.test(text)).toBe(false);
  });
  it('is not within baseline when a wave has missing required logs', async () => {
    const dir = await generateScenario();
    const mp = join(dir, 'manifest.json');
    const m = JSON.parse(readFileSync(mp, 'utf-8'));
    const log = m.logs.find((l: { type: string; day: string }) => l.type === 'AuraRequest' && l.day === '2026-09-15');
    log.status = 'missing';
    writeFileSync(mp, JSON.stringify(m));
    const res = await analyseBundle(dir);
    expect(res.waves.find((w) => w.wave.days.includes('2026-09-15'))!.requiredLogsPresent).toBe(false);
    expect(res.withinBaseline).toBe(false);
  });
});

describe('withinBaseline on a quiet wave', () => {
  const quiet = [{ id: 'W1', guestId15: GUEST_A, site: SITE_A, days: ['2026-09-14'], eventIds: [] }];
  async function quietBundle(markSitesMissing: boolean): Promise<string> {
    const dir = await generateScenario();
    const mp = join(dir, 'manifest.json');
    const m = JSON.parse(readFileSync(mp, 'utf-8'));
    m.waves = quiet;
    if (markSitesMissing) {
      const log = m.logs.find((l: { type: string; day: string }) => l.type === 'Sites' && l.day === '2026-09-14');
      log.status = 'missing';
      delete log.file;
    }
    writeFileSync(mp, JSON.stringify(m));
    return dir;
  }
  it('is within baseline when every log is collected', async () => {
    const res = await analyseBundle(await quietBundle(false));
    expect(res.withinBaseline).toBe(true);
    expect(res.waves[0].result).toBe('no-evidence');
  });
  it('is not within baseline when the Sites log is missing', async () => {
    const res = await analyseBundle(await quietBundle(true));
    expect(res.withinBaseline).toBe(false);
    expect(res.waves[0].result).toBe('not-assessed');
  });
});
