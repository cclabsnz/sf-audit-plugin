import { getCheckMeta, CHECK_META } from '../../../src/findings/CheckMeta.js';
import { CHECKS } from '../../../src/checks/registry.js';

describe('CheckMeta', () => {
  it('returns effort and impact for a known check', () => {
    const m = getCheckMeta('internal-user-mfa');
    expect(m).toBeDefined();
    expect(['quick', 'moderate', 'project']).toContain(m?.effort);
    expect((m?.impact.length ?? 0)).toBeGreaterThan(10);
  });

  it('every effort value is a valid tier', () => {
    for (const m of Object.values(CHECK_META)) {
      expect(['quick', 'moderate', 'project']).toContain(m.effort);
    }
  });

  it('every impact is a non-trivial sentence', () => {
    for (const m of Object.values(CHECK_META)) {
      expect(m.impact.length).toBeGreaterThan(20);
    }
  });

  it('every registered check has a CheckMeta entry', () => {
    const missing = CHECKS.map((c) => c.id).filter((id) => !CHECK_META[id]);
    expect(missing).toEqual([]);
  });
});
