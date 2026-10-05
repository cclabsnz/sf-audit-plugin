import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, SITE_A, SITE_B } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { computeConfigDelta } from '../../../src/incident/analyse/configDelta.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('computeConfigDelta', () => {
  it('splits changes into before / between / after and excludes self-registrations', () => {
    const { periods } = computeConfigDelta(b.audit, b.manifest.guests, b.manifest.waves);
    expect(periods.map((p) => p.label)).toEqual(['Before 2026-06-30', '2026-06-30 to 2026-09-15', 'After 2026-09-15']);
    const between = periods[1];
    expect(between.bySite[SITE_B]).toHaveLength(10);
    expect(between.bySite[SITE_A]).toHaveLength(1);
    expect(Object.values(between.bySite).flat().some((c) => c.display.startsWith('Created new Customer User'))).toBe(false);
  });
  it('flags W3: site A was hit again after fewer changes than site B', () => {
    const { asymmetries } = computeConfigDelta(b.audit, b.manifest.guests, b.manifest.waves);
    expect(asymmetries).toEqual([{ waveId: 'W3', site: SITE_A, changes: 1, comparedSite: SITE_B, comparedChanges: 10, period: '2026-06-30 to 2026-09-15' }]);
  });
});
