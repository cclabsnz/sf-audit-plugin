import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateScenario, SITE_A, SITE_B } from '../../fixtures/incident/generate.js';
import { loadBundle, type Bundle } from '../../../src/incident/bundleIo.js';
import { computeConfigDelta, type Period } from '../../../src/incident/analyse/configDelta.js';

let b: Bundle;
beforeAll(async () => { b = await loadBundle(await generateScenario()); });

describe('computeConfigDelta', () => {
  it('splits changes into before / between / after and excludes self-registrations', () => {
    const { periods } = computeConfigDelta(b.audit, b.manifest.guests, b.manifest.waves);
    // I7: each wave span gets its own "During" period between the before/between/after ones.
    expect(periods.map((p) => p.label)).toEqual(['Before 2026-06-30', 'During W1, W2 (2026-06-30)', '2026-06-30 to 2026-09-15', 'During W3 (2026-09-15)', 'After 2026-09-15']);
    const between = periods.find((p) => p.label === '2026-06-30 to 2026-09-15')!;
    expect(between.bySite[SITE_B]).toHaveLength(10);
    expect(between.bySite[SITE_A]).toHaveLength(1);
    expect(Object.values(between.bySite).flat().some((c) => c.display.startsWith('Created new Customer User'))).toBe(false);
  });
  it('flags W3: site A was hit again after fewer changes than site B', () => {
    const { asymmetries } = computeConfigDelta(b.audit, b.manifest.guests, b.manifest.waves);
    expect(asymmetries).toEqual([{ waveId: 'W3', site: SITE_A, changes: 1, comparedSite: SITE_B, comparedChanges: 10, period: '2026-06-30 to 2026-09-15' }]);
  });
});

/** The period between the two waves (I7 inserted "During" periods, so it is no longer index 1). */
const between = (ps: Period[]): Period => ps.find((p) => / to /.test(p.label) && !p.label.startsWith('During'))!;

describe('computeConfigDelta attribution', () => {
  const guest = (id15: string, name: string, site: string, profileName: string, permissionSetLabels: string[] = []) =>
    ({ id15, username: `${id15}@example.com`, name, profileName, permissionSetLabels, siteNames: [site], active: true });
  const row = (display: string, createdDate = '2026-07-05T10:00:00Z') => ({ createdDate, createdBy: 'Admin', section: null, action: 'x', display });
  const waves = [
    { id: 'W1', guestId15: '005xx000000gstA', site: 'S1', days: ['2026-06-30'], eventIds: [] },
    { id: 'W2', guestId15: '005xx000000gstB', site: 'S2', days: ['2026-09-15'], eventIds: [] },
  ];

  it('(a) does not match a short label inside a longer word', () => {
    const { periods } = computeConfigDelta([row('Template log updated')], [guest('005xx000000gstA', 'U1', 'ATE', 'P1')], waves);
    expect(between(periods).bySite).toEqual({});
  });
  it('(b) does not credit "Site A" for "Site AB"', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'Site A', 'Site A Guest Profile'), guest('005xx000000gstB', 'U2', 'Site AB', 'Site AB Guest Profile')];
    const { periods } = computeConfigDelta([row('Changed profile Site AB Guest Profile')], gs, waves);
    expect(Object.keys(between(periods).bySite)).toEqual(['Site AB']);
  });
  it('(c) a shared label goes to period.shared, to no site, and never affects asymmetry', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'S1', 'P1', ['Shared Files']), guest('005xx000000gstB', 'U2', 'S2', 'P2', ['shared files'])];
    const { periods, asymmetries } = computeConfigDelta([row('Permission set Shared Files changed')], gs, waves);
    expect(between(periods).shared).toHaveLength(1);
    expect(between(periods).bySite).toEqual({});
    expect(asymmetries).toEqual([]);
  });
  it('(d) a change matching several unique labels of one site counts once for that site', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'S1', 'P1'), guest('005xx000000gstB', 'U2', 'S2', 'P2')];
    const { periods } = computeConfigDelta([row('P1 and U1 and S1 plus P2')], gs, waves);
    expect(between(periods).bySite['S1']).toHaveLength(1);
    expect(between(periods).bySite['S2']).toHaveLength(1);
  });
});

describe('computeConfigDelta wave-day changes (I7)', () => {
  it('a change made on a wave day appears in that wave\'s "During" period, and asymmetry ignores it', () => {
    const onD2 = { createdDate: '2026-09-15T03:00:00Z', createdBy: 'Admin One', section: 'Manage Users', action: 'profileChanged', display: 'Changed profile Site A Guest Profile: tab x was hidden' };
    const { periods, asymmetries } = computeConfigDelta([...b.audit, onD2], b.manifest.guests, b.manifest.waves);
    const during = periods.find((p) => p.label === 'During W3 (2026-09-15)')!;
    expect(during.bySite[SITE_A]).toEqual([expect.objectContaining({ at: onD2.createdDate })]);
    expect(asymmetries).toEqual([{ waveId: 'W3', site: SITE_A, changes: 1, comparedSite: SITE_B, comparedChanges: 10, period: '2026-06-30 to 2026-09-15' }]);
  });
  it('labels a multi-day wave by its first and last day', () => {
    const waves = [{ id: 'W1', guestId15: '005xx000000gstA', site: 'S1', days: ['2026-06-30', '2026-07-01'], eventIds: [] }];
    expect(computeConfigDelta([], [], waves).periods.map((p) => p.label)).toEqual(['Before 2026-06-30', 'During W1 (2026-06-30 to 2026-07-01)', 'After 2026-07-01']);
  });
});
