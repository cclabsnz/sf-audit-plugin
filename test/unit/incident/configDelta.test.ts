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

describe('computeConfigDelta attribution', () => {
  const guest = (id15: string, name: string, site: string, profileName: string, permissionSetLabels: string[] = []) =>
    ({ id15, username: `${id15}@example.com`, name, profileName, permissionSetLabels, siteNames: [site], active: true });
  const row = (display: string, createdDate = '2026-07-05T10:00:00Z') => ({ createdDate, createdBy: 'Admin', section: null, action: 'x', display });
  const waves = [
    { id: 'W1', guestId15: '005xx000000gstA', site: 'S1', days: ['2026-06-30'], eventIds: [] },
    { id: 'W2', guestId15: '005xx000000gstB', site: 'S2', days: ['2026-09-15'], eventIds: [] },
  ];

  it('(a) does not match a short label inside a longer word', () => {
    const { periods } = computeConfigDelta([row('Repair log updated')], [guest('005xx000000gstA', 'U1', 'AIR', 'P1')], waves);
    expect(periods[1].bySite).toEqual({});
  });
  it('(b) does not credit "Site A" for "Site AB"', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'Site A', 'Site A Guest Profile'), guest('005xx000000gstB', 'U2', 'Site AB', 'Site AB Guest Profile')];
    const { periods } = computeConfigDelta([row('Changed profile Site AB Guest Profile')], gs, waves);
    expect(Object.keys(periods[1].bySite)).toEqual(['Site AB']);
  });
  it('(c) a shared label goes to period.shared, to no site, and never affects asymmetry', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'S1', 'P1', ['Shared Files']), guest('005xx000000gstB', 'U2', 'S2', 'P2', ['shared files'])];
    const { periods, asymmetries } = computeConfigDelta([row('Permission set Shared Files changed')], gs, waves);
    expect(periods[1].shared).toHaveLength(1);
    expect(periods[1].bySite).toEqual({});
    expect(asymmetries).toEqual([]);
  });
  it('(d) a change matching several unique labels of one site counts once for that site', () => {
    const gs = [guest('005xx000000gstA', 'U1', 'S1', 'P1'), guest('005xx000000gstB', 'U2', 'S2', 'P2')];
    const { periods } = computeConfigDelta([row('P1 and U1 and S1 plus P2')], gs, waves);
    expect(periods[1].bySite['S1']).toHaveLength(1);
    expect(periods[1].bySite['S2']).toHaveLength(1);
  });
});
