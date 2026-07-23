import type { AppCategory } from './types.js';

export interface StandardApp {
  name: string;
  category: AppCategory;
  vendor: string;
  purpose: string;
}

// Curated seed of common connected-app ids (15-char keys). Salesforce standard-app ids are
// stable across orgs; third-party ids are the ones observed in practice. Grow over time.
export const STANDARD_APPS: Record<string, StandardApp> = {
  '0H44a00000000Ns': { name: 'Dataloader Bulk', category: 'Salesforce-standard', vendor: 'Salesforce', purpose: 'Bulk data import/export tool' },
  '0H44a00000000Nt': { name: 'Dataloader Partner', category: 'Salesforce-standard', vendor: 'Salesforce', purpose: 'Data Loader (SOAP) tool' },
  '0H44a00000000Nz': { name: 'Workbench', category: 'Salesforce-standard', vendor: 'Salesforce', purpose: 'Ad-hoc API/data tool' },
  '0H44a00000000Nu': { name: 'Force.com IDE', category: 'Salesforce-standard', vendor: 'Salesforce', purpose: 'Developer tooling' },
};

/** Look up a connected-app id (15- or 18-char) in the bundled catalog. */
export function lookupStandardApp(appId: string): StandardApp | null {
  const key = appId.slice(0, 15);
  return STANDARD_APPS[key] ?? null;
}
