import { lookupStandardApp } from '../../../src/apps/standardAppCatalog.js';

describe('standardAppCatalog', () => {
  it('resolves a well-known Salesforce standard app id to name + category', () => {
    const hit = lookupStandardApp('0H44a00000000Ns'); // Dataloader Bulk
    expect(hit?.name).toBe('Dataloader Bulk');
    expect(hit?.category).toBe('Salesforce-standard');
    expect(hit?.vendor).toBe('Salesforce');
  });

  it('returns null for an unknown id', () => {
    expect(lookupStandardApp('888xUNKNOWN0000')).toBeNull();
  });

  it('normalises an 18-char id to its 15-char key', () => {
    expect(lookupStandardApp('0H44a00000000NsAAI')?.name).toBe('Dataloader Bulk');
  });
});
