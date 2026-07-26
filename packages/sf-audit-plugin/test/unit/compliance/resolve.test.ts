import { resolveControls, packFrameworks, getComplianceTags } from '../../../src/compliance/resolve.js';

describe('resolveControls', () => {
  it('returns only controls in the selected frameworks', () => {
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: false });
    expect(out.every((c) => c.framework === 'ISO27001')).toBe(true);
    expect(out.length).toBeGreaterThan(0);
  });

  it('returns only verified controls when requireVerified is true (provenance gate)', () => {
    // The gate filters out any control whose verified flag is false; with the catalog fully
    // verified, every returned control is verified — and a draft would never appear.
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: true });
    expect(out.every((c) => c.verified)).toBe(true);
  });

  it('defaults requireVerified to true and returns only verified controls', () => {
    const out = resolveControls('users-and-admins');
    expect(out.length).toBeGreaterThan(0);          // OWASP/Privacy Act controls are verified
    expect(out.every((c) => c.verified)).toBe(true); // never returns a draft
  });

  it('packFrameworks maps universal to OWASP/OWASP_LLM/SOC2/ISO', () => {
    expect(packFrameworks('universal').sort()).toEqual(['ISO27001', 'OWASP', 'OWASP_LLM', 'SOC2']);
  });

  it('the nz pack includes HISO, Privacy Act, and NZISM', () => {
    const nz = packFrameworks('nz');
    expect(nz).toContain('HISO10029');
    expect(nz).toContain('PRIVACY_ACT');
    expect(nz).toContain('NZISM');
  });

  it('resolves NZ controls for a check (provenance off, drafts)', () => {
    const out = resolveControls('guest-user-access', { frameworks: ['HISO10029', 'PRIVACY_ACT'], requireVerified: false });
    expect(out.some((c) => c.framework === 'HISO10029')).toBe(true);
    expect(out.some((c) => c.id === 'PRIVACY-IPP5')).toBe(true);
  });
});

describe('getComplianceTags (compat shim)', () => {
  it('returns the raw id strings for a check, unchanged from the old behaviour', () => {
    const tags = getComplianceTags('users-and-admins');
    expect(tags).toContain('OWASP-A01');
    expect(tags).toContain('ISO-A.5.18'); // ISO/IEC 27001:2022 Annex A 5.18 Access rights
  });

  it('returns an empty array for an unknown check', () => {
    expect(getComplianceTags('nope')).toEqual([]);
  });
});
