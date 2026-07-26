export interface Branding {
  firmName: string;
  primary: string;       // hex
  ink: string;
  bg: string;
  bgAlt: string;
  muted: string;
  border: string;
  fontDisplay: string;
  fontBody: string;
  contact: string;
  website?: string;
  logoPath?: string;
  preparedFor?: string;
}

export const DEFAULT_BRANDING: Branding = {
  firmName: 'CloudCounsel Limited',
  primary: '#3a5a82',
  ink: '#1a1d24',
  bg: '#faf6ef',
  bgAlt: '#f7f7f2',
  muted: '#636770',
  border: '#e9e9e3',
  fontDisplay: 'DM Serif Display',
  fontBody: 'DM Sans',
  contact: 'hello@cloudcounsel.co.nz',
  website: 'cloudcounsel.co.nz',
};

export type BrandingOverrides = Partial<Branding>;

export function resolveBranding(
  overrides: BrandingOverrides | undefined,
  preparedFor: string | undefined,
): Branding {
  const merged: Branding = { ...DEFAULT_BRANDING, ...(overrides ?? {}) };
  if (preparedFor) merged.preparedFor = preparedFor;
  return merged;
}
