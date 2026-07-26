import { describe, it, expect } from '@jest/globals';
import { runProbe } from '../../../src/probe/runProbe.js';
import type { IntelContext } from '../../../src/lib/wire.js';
import { mockSoql, mockRest, noopTooling, noopMetadata } from '../helpers/mocks.js';

function context(): IntelContext {
  const rest = mockRest([
    { name: 'Account', custom: false, queryable: true },
    { name: 'AccountHistory', custom: false, queryable: true },
    { name: 'Case', custom: false, queryable: true },
    { name: 'Opportunity', custom: false, queryable: true },
    { name: 'FieldHistoryArchive', custom: false, queryable: true },
    { name: 'Claim__c', custom: true, queryable: true },
    { name: 'Claim__History', custom: true, queryable: true },
  ]);

  const soql = mockSoql([
    {
      test: (q) => q.includes('FROM EventLogFile'),
      records: [
        { EventType: 'ApiTotalUsage', Interval: 'Hourly' },
        { EventType: 'Login', Interval: 'Daily' },
      ],
    },
    { test: (q) => q.includes('FROM AccountHistory') && q.includes('GROUP BY Field'), records: [{ Field: 'Owner' }] },
    { test: (q) => q.includes('FROM Claim__History') && q.includes('GROUP BY Field'), records: [{ Field: 'Status__c' }] },
    { test: (q) => q.includes("InterviewStatus = 'Paused'"), totalSize: 2 },
    { test: (q) => q.includes("InterviewStatus = 'Error'"), totalSize: 0 },
    // generic COUNT() catch-all for every behavioural table
    { test: (q) => q.startsWith('SELECT COUNT()'), totalSize: 9 },
  ]);

  return {
    soql,
    tooling: noopTooling,
    rest,
    metadata: noopMetadata,
    orgInfo: {
      id: '00Dxx0000001gPZEAY',
      name: 'Acme Health',
      type: 'Enterprise Edition',
      isSandbox: false,
      instance: 'NA123',
      instanceUrl: 'https://acme.my.salesforce.com',
    },
    apiVersion: '62.0',
    namespace: null,
  };
}

describe('runProbe (integration)', () => {
  it('produces a full, deterministic probe over a rich org', async () => {
    const a = await runProbe(context());
    const b = await runProbe(context());
    expect(a).toEqual(b); // deterministic

    expect(a.org.name).toBe('Acme Health');
    expect(a.org.organizationType).toBe('Enterprise Edition');
    expect(a.eventMonitoring.level).toBe('full');
    // full EM + FieldHistoryArchive present -> tier A
    expect(a.evidenceTier).toBe('A');
    expect(a.fieldHistory.fieldAuditTrail).toBe(true);
    expect(a.fieldHistory.trackedObjectCount).toBe(2); // Account + Claim__c
    expect(a.coverage).toHaveLength(3);
    // AccountHistory got added as an extra behavioural table
    expect(a.behavioralTables.tables.map((t) => t.name)).toContain('AccountHistory');
  });

  it('degrades to a low tier when nothing is readable', async () => {
    const rest = mockRest([]); // empty catalog
    const soql = mockSoql([
      { test: (q) => q.includes('FROM EventLogFile'), error: new Error("sObject type 'EventLogFile' is not supported") },
      { test: (q) => q.startsWith('SELECT COUNT()'), error: new Error("is not supported") },
    ]);
    const ctx: IntelContext = { ...context(), rest, soql };
    const data = await runProbe(ctx);
    expect(data.eventMonitoring.level).toBe('none');
    expect(['C', 'D']).toContain(data.evidenceTier);
    expect(data.recommendations.length).toBeGreaterThan(0);
  });
});
