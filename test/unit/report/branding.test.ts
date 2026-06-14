import { resolveBranding, DEFAULT_BRANDING } from '../../../src/report/branding.js';

describe('resolveBranding', () => {
  it('returns CloudCounsel defaults when no overrides', () => {
    const b = resolveBranding(undefined, undefined);
    expect(b.firmName).toBe('CloudCounsel Limited');
    expect(b.primary).toBe('#3a5a82');
    expect(b.fontBody).toBe('DM Sans');
  });

  it('applies overrides over defaults', () => {
    const b = resolveBranding({ primary: '#000000', firmName: 'Acme' }, 'Client X');
    expect(b.primary).toBe('#000000');
    expect(b.firmName).toBe('Acme');
    expect(b.preparedFor).toBe('Client X');
    expect(b.fontBody).toBe(DEFAULT_BRANDING.fontBody);
  });

  it('preparedFor argument wins over file value', () => {
    const b = resolveBranding({ preparedFor: 'File Co' }, 'Flag Co');
    expect(b.preparedFor).toBe('Flag Co');
  });
});
