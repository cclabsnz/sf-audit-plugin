import { describe, it, expect } from '@jest/globals';
import { probeFieldHistory } from '../../../src/probe/fieldHistory.js';
import { buildCatalog } from '../../../src/probe/sobjectCatalog.js';
import { mockSoql } from '../helpers/mocks.js';

const catalog = buildCatalog([
  { name: 'Account', label: 'Account', custom: false, queryable: true },
  { name: 'AccountHistory', label: 'Account History', custom: false, queryable: true },
  { name: 'Case', label: 'Case', custom: false, queryable: true }, // no CaseHistory -> untracked
  { name: 'Claim__c', label: 'Claim', custom: true, queryable: true },
  { name: 'Claim__History', label: 'Claim History', custom: true, queryable: true },
  { name: 'FieldHistoryArchive', label: 'Field History Archive', custom: false, queryable: true },
]);

const soql = mockSoql([
  { test: (q) => q.includes('FROM AccountHistory'), records: [{ Field: 'Owner' }, { Field: 'Name' }] },
  { test: (q) => q.includes('FROM Claim__History'), records: [{ Field: 'Status__c' }] },
]);

describe('probeFieldHistory', () => {
  it('detects tracked objects, tracked fields, and Field Audit Trail', async () => {
    const fh = await probeFieldHistory(soql, catalog);

    const account = fh.objects.find((o) => o.object === 'Account')!;
    expect(account.historyTrackingEnabled).toBe(true);
    expect(account.trackedFields).toEqual(['Name', 'Owner']);
    expect(account.trackedFieldCount).toBe(2);
    expect(account.atCap).toBe(false);

    const cse = fh.objects.find((o) => o.object === 'Case')!;
    expect(cse.historyTrackingEnabled).toBe(false);
    expect(cse.trackedFieldCount).toBeNull();

    const claim = fh.objects.find((o) => o.object === 'Claim__c')!;
    expect(claim.custom).toBe(true);
    expect(claim.historyTrackingEnabled).toBe(true);
    expect(claim.trackedFields).toEqual(['Status__c']);

    expect(fh.fieldAuditTrail).toBe(true);
    expect(fh.trackedObjectCount).toBe(2);
  });

  it('degrades gracefully when the tracked-field aggregate is not permitted', async () => {
    const soqlDenied = mockSoql([
      { test: (q) => q.includes('FROM AccountHistory'), error: new Error('aggregate not allowed') },
      { test: (q) => q.includes('FROM Claim__History'), records: [] },
    ]);
    const fh = await probeFieldHistory(soqlDenied, catalog);
    const account = fh.objects.find((o) => o.object === 'Account')!;
    expect(account.historyTrackingEnabled).toBe(true);
    expect(account.trackedFieldCount).toBeNull();
    expect(account.note).toMatch(/not permitted/i);
  });
});
