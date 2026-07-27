import { describe, it, expect } from '@jest/globals';
import { runDiscover } from '../../../src/discover/runDiscover.js';
import type { IntelContext } from '../../../src/lib/wire.js';
import { mockSoql, mockTooling, mockRest, noopMetadata } from '../helpers/mocks.js';

const CATALOG = [
  { name: 'Account', label: 'Account', custom: false, queryable: true },
  { name: 'AccountHistory', label: 'Account History', custom: false, queryable: true },
  { name: 'Contact', label: 'Contact', custom: false, queryable: true },
  { name: 'Opportunity', label: 'Opportunity', custom: false, queryable: true },
  { name: 'Case', label: 'Case', custom: false, queryable: true },
  { name: 'CaseHistory', label: 'Case History', custom: false, queryable: true },
  { name: 'Claim__c', label: 'Claim', custom: true, queryable: true },
  { name: 'Claim__History', label: 'Claim History', custom: true, queryable: true },
];

const DESCRIBES = {
  Case: {
    name: 'Case',
    label: 'Case',
    custom: false,
    fields: [
      {
        name: 'Status',
        label: 'Status',
        type: 'picklist',
        picklistValues: [{ value: 'New' }, { value: 'Working' }, { value: 'Closed' }],
      },
    ],
    childRelationships: [
      { childSObject: 'CaseComment', field: 'ParentId' },
      { childSObject: 'CaseHistory', field: 'CaseId' },
    ],
  },
  Account: {
    name: 'Account',
    label: 'Account',
    custom: false,
    fields: [],
    childRelationships: [
      { childSObject: 'Contact', field: 'AccountId' },
      { childSObject: 'Opportunity', field: 'AccountId' },
      { childSObject: 'Case', field: 'AccountId' },
    ],
  },
};

function context(): IntelContext {
  return {
    soql: mockSoql([
      // FlowDefinitionView is a STANDARD object — it must arrive on the SOQL client, never Tooling.
      {
        test: (q) => q.includes('FROM FlowDefinitionView'),
        records: [{ TriggerType: 'RecordAfterSave', TriggerObjectOrEventLabel: 'Case', IsActive: true }],
      },
      { test: (q) => q.includes('FROM ProcessDefinition'), records: [] },
      { test: (q) => q.includes('FROM RecordType'), records: [{ SobjectType: 'Case', DeveloperName: 'Support', Name: 'Support' }] },
      { test: (q) => q.includes('FROM AppMenuItem'), records: [{ Label: 'Service', Name: 'std__service' }] },
      { test: (q) => q.startsWith('SELECT COUNT()'), totalSize: 500 },
    ]),
    tooling: mockTooling([
      { test: (q) => q.includes('FROM EntityDefinition'), records: [{ QualifiedApiName: 'Case', DurableId: 'Case', KeyPrefix: '500' }] },
      {
        test: (q) => q.includes('FROM ApexTrigger'),
        records: [
          { TableEnumOrId: 'Case', Status: 'Active' },
          { TableEnumOrId: 'Case', Status: 'Active' },
        ],
      },
      { test: (q) => q.includes('FROM WorkflowRule'), records: [] },
      { test: (q) => q.includes('FROM InstalledSubscriberPackage'), records: [] },
    ]),
    rest: mockRest(CATALOG, DESCRIBES),
    metadata: noopMetadata,
    orgInfo: { id: '00Dxx', name: 'Acme', type: 'Enterprise Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
    apiVersion: '62.0',
    namespace: null,
  };
}

describe('runDiscover (integration)', () => {
  it('ranks anchors and emits a domain fingerprint deterministically', async () => {
    const a = await runDiscover(context());
    const b = await runDiscover(context());
    expect(a).toEqual(b);

    expect(a.totalObjectsAnalyzed).toBe(5); // Account, Contact, Opportunity, Case, Claim__c
    expect(a.anchors[0].object).toBe('Case'); // automation + status + history + centrality
    expect(a.anchors[1].object).toBe('Account'); // relationship hub + history

    const caseAnchor = a.anchors[0];
    expect(caseAnchor.signals.automation.total).toBe(3); // 2 triggers + 1 flow
    expect(caseAnchor.signals.statusField?.field).toBe('Status');
    expect(caseAnchor.signals.historyTracking).toBe(true);
    expect(caseAnchor.evidence.length).toBeGreaterThan(0);

    expect(a.fingerprint.recordTypes).toHaveLength(1);
    expect(a.fingerprint.apps).toEqual(['Service']);
    expect(a.fingerprint.clouds).toContain('Service Cloud');
    expect(a.weights.automation).toBeCloseTo(0.3, 5);
  });
});
