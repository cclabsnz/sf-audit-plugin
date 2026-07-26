import { describe, it, expect } from '@jest/globals';
import { probeBehavioralTables } from '../../../src/probe/behavioralTables.js';
import { mockSoql } from '../helpers/mocks.js';

describe('probeBehavioralTables', () => {
  it('reports ok/no-access/not-present and FlowInterview extras', async () => {
    const soql = mockSoql([
      // FlowInterview status snapshots must be matched before the generic 12mo count
      { test: (q) => q.includes("InterviewStatus = 'Paused'"), totalSize: 3 },
      { test: (q) => q.includes("InterviewStatus = 'Error'"), totalSize: 1 },
      { test: (q) => q.includes('FROM OpportunityFieldHistory'), totalSize: 42 },
      { test: (q) => q.includes('FROM CaseHistory'), totalSize: 100 },
      { test: (q) => q.includes('FROM ProcessInstanceStep'), error: new Error('INSUFFICIENT_ACCESS on ProcessInstanceStep') },
      { test: (q) => q.includes('FROM ProcessInstance WHERE'), error: new Error("sObject type 'ProcessInstance' is not supported") },
      { test: (q) => q.includes('FROM FlowInterview'), totalSize: 7 },
      { test: (q) => q.includes('FROM AsyncApexJob'), totalSize: 12 },
      { test: (q) => q.includes('FROM SetupAuditTrail'), totalSize: 88 },
    ]);

    const { tables } = await probeBehavioralTables(soql);
    const byName = Object.fromEntries(tables.map((t) => [t.name, t]));

    expect(byName.OpportunityFieldHistory.access).toBe('ok');
    expect(byName.OpportunityFieldHistory.rowCount12mo).toBe(42);
    expect(byName.ProcessInstance.access).toBe('not-present');
    expect(byName.ProcessInstance.rowCount12mo).toBeNull();
    expect(byName.ProcessInstanceStep.access).toBe('no-access');
    expect(byName.FlowInterview.rowCount12mo).toBe(7);
    expect(byName.FlowInterview.extra).toEqual({ paused: 3, error: 1 });
    expect(byName.SetupAuditTrail.rowCount12mo).toBe(88);
  });

  it('includes extra history tables passed in, de-duplicated', async () => {
    const soql = mockSoql([{ test: () => true, totalSize: 1 }]);
    const { tables } = await probeBehavioralTables(soql, ['AccountHistory', 'CaseHistory']);
    const names = tables.map((t) => t.name);
    expect(names).toContain('AccountHistory');
    // CaseHistory is already a core table — must not be duplicated
    expect(names.filter((n) => n === 'CaseHistory')).toHaveLength(1);
  });
});
