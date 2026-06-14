import { getControl, ALL_CONTROLS } from '../../../src/compliance/catalogs/index.js';

describe('catalog lookup', () => {
  it('returns a control by id', () => {
    const c = getControl('OWASP-A01');
    expect(c).toBeDefined();
    expect(c?.framework).toBe('OWASP');
    expect(typeof c?.requirement).toBe('string');
    expect(c?.requirement.length).toBeGreaterThan(0);
  });

  it('returns undefined for an unknown id', () => {
    expect(getControl('NOPE-999')).toBeUndefined();
  });

  it('has no duplicate control ids across catalogs', () => {
    const ids = ALL_CONTROLS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
