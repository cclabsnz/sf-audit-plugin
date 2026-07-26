import { describe, it, expect } from '@jest/globals';
import { buildAutomationIndex } from '../../../src/discover/automation.js';
import { resolverFromEntities } from '../../../src/discover/objectResolver.js';
import { buildCatalog } from '../../../src/probe/sobjectCatalog.js';
import { mockSoql, mockTooling } from '../helpers/mocks.js';

const catalog = buildCatalog([
  { name: 'Account', label: 'Account', custom: false, queryable: true },
  { name: 'Case', label: 'Case', custom: false, queryable: true },
  { name: 'Claim__c', label: 'Claim', custom: true, queryable: true },
]);

const resolver = resolverFromEntities([
  { QualifiedApiName: 'Account', DurableId: 'Account', KeyPrefix: '001' },
  { QualifiedApiName: 'Claim__c', DurableId: '01I5x000000AbcDEAU', KeyPrefix: 'a0X' },
]);

const tooling = mockTooling([
  {
    test: (q) => q.includes('FROM ApexTrigger'),
    records: [
      { TableEnumOrId: 'Account', Status: 'Active' },
      { TableEnumOrId: '01I5x000000AbcDEAU', Status: 'Active' }, // custom -> Claim__c
      { TableEnumOrId: 'Account', Status: 'Inactive' }, // skipped
    ],
  },
  { test: (q) => q.includes('FROM WorkflowRule'), records: [{ TableEnumOrId: 'Account' }] },
  {
    test: (q) => q.includes('FROM FlowDefinitionView'),
    records: [
      { TriggerType: 'RecordAfterSave', TriggerObjectOrEventLabel: 'Account', IsActive: true },
      { TriggerType: 'RecordBeforeSave', TriggerObjectOrEventLabel: 'Case', IsActive: true },
      { TriggerType: 'Scheduled', TriggerObjectOrEventLabel: 'Account', IsActive: true }, // not record-triggered
      { TriggerType: 'RecordAfterSave', TriggerObjectOrEventLabel: 'Account', IsActive: false }, // inactive
    ],
  },
]);

const soql = mockSoql([
  {
    test: (q) => q.includes('FROM ProcessDefinition'),
    records: [{ TableEnumOrId: 'Account', Type: 'Approval', State: 'Active' }],
  },
]);

describe('buildAutomationIndex', () => {
  it('aggregates automation per object with exact resolution and label-matched flows', async () => {
    const idx = await buildAutomationIndex(soql, tooling, resolver, catalog);

    const account = idx.countsFor('Account');
    expect(account).toEqual({ flows: 1, triggers: 1, approvals: 1, workflowRules: 1, total: 4 });

    const claim = idx.countsFor('Claim__c');
    expect(claim.triggers).toBe(1);
    expect(claim.total).toBe(1);

    const cse = idx.countsFor('Case');
    expect(cse.flows).toBe(1);
    expect(cse.total).toBe(1);

    expect(idx.automatedObjects()).toEqual(new Set(['Account', 'Claim__c', 'Case']));
  });

  it('degrades to zero when a source query fails', async () => {
    const brokenTooling = mockTooling([
      { test: (q) => q.includes('FROM ApexTrigger'), error: new Error('boom') },
      { test: (q) => q.includes('FROM WorkflowRule'), records: [] },
      { test: (q) => q.includes('FROM FlowDefinitionView'), records: [] },
    ]);
    const brokenSoql = mockSoql([{ test: (q) => q.includes('FROM ProcessDefinition'), records: [] }]);
    const idx = await buildAutomationIndex(brokenSoql, brokenTooling, resolver, catalog);
    expect(idx.countsFor('Account').total).toBe(0);
    expect(idx.notes.some((n) => n.includes('Apex triggers'))).toBe(true);
  });
});
