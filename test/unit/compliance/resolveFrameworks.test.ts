import { resolveFrameworks } from '../../../src/compliance/resolve.js';

describe('resolveFrameworks', () => {
  it('resolves pack names', () => {
    expect(resolveFrameworks('universal').sort()).toEqual(['ISO27001', 'OWASP', 'SOC2']);
    expect(resolveFrameworks('nz')).toContain('NZISM');
    expect(resolveFrameworks('all')).toContain('HIPAA');
  });
  it('resolves an explicit comma list of aliases', () => {
    expect(resolveFrameworks('owasp,iso,nzism').sort()).toEqual(['ISO27001', 'NZISM', 'OWASP']);
  });
  it('ignores unknown aliases', () => {
    expect(resolveFrameworks('owasp,bogus')).toEqual(['OWASP']);
  });
});
