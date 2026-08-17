import { getControl, ALL_CONTROLS } from '../../../src/compliance/catalogs/index.js';
import { packFrameworks } from '../../../src/compliance/resolve.js';

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

  it('contains the universal frameworks, SBS, the NZ pack, and HIPAA/GDPR', () => {
    const frameworks = new Set(ALL_CONTROLS.map((c) => c.framework));
    for (const fw of ['OWASP', 'OWASP_LLM', 'SOC2', 'ISO27001', 'SBS', 'HISO10029', 'PRIVACY_ACT',
                      'NZISM', 'HIPAA', 'GDPR']) {
      expect(frameworks.has(fw as never)).toBe(true);
    }
  });

  // Every framework named in the `all` pack must actually have controls behind it. Before the
  // HIPAA/GDPR catalogs landed, both sat in the pack contributing nothing, so `--frameworks all`
  // silently rendered zero rows for them.
  it('every framework in the `all` pack has catalogued controls', () => {
    const populated = new Set(ALL_CONTROLS.map((c) => c.framework));
    for (const fw of packFrameworks('all')) {
      expect(populated.has(fw)).toBe(true);
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
