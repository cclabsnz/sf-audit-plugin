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

  it('contains the universal frameworks plus SBS', () => {
    const frameworks = new Set(ALL_CONTROLS.map((c) => c.framework));
    for (const fw of ['OWASP', 'SOC2', 'ISO27001', 'SBS']) {
      expect(frameworks.has(fw as never)).toBe(true);
    }
  });

  it('every control has the required shape', () => {
    for (const c of ALL_CONTROLS) {
      expect(c.id).toMatch(/.+/);
      expect(c.title).toMatch(/.+/);
      expect(c.requirement.length).toBeGreaterThan(10);
      expect(c.sourceRef).toMatch(/.+/);
      expect(c.version).toMatch(/.+/);
      expect(typeof c.verified).toBe('boolean');
    }
  });
});
