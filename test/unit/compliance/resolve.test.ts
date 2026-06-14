import { resolveControls, packFrameworks, getComplianceTags } from '../../../src/compliance/resolve.js';

describe('resolveControls', () => {
  it('returns only controls in the selected frameworks', () => {
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: false });
    expect(out.every((c) => c.framework === 'ISO27001')).toBe(true);
    expect(out.length).toBeGreaterThan(0);
  });

  it('excludes unverified controls when requireVerified is true', () => {
    // catalogs ship verified:false, so a verified-only resolve is empty for now
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: true });
    expect(out).toEqual([]);
  });

  it('defaults requireVerified to true', () => {
    expect(resolveControls('users-and-admins')).toEqual([]);
  });

  it('packFrameworks maps universal to OWASP/SOC2/ISO', () => {
    expect(packFrameworks('universal').sort()).toEqual(['ISO27001', 'OWASP', 'SOC2']);
  });
});

describe('getComplianceTags (compat shim)', () => {
  it('returns the raw id strings for a check, unchanged from the old behaviour', () => {
    const tags = getComplianceTags('users-and-admins');
    expect(tags).toContain('OWASP-A01');
    expect(tags).toContain('ISO-A.9.2');
  });

  it('returns an empty array for an unknown check', () => {
    expect(getComplianceTags('nope')).toEqual([]);
  });
});
