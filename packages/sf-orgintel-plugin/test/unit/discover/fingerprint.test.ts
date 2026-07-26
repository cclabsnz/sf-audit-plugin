import { describe, it, expect } from '@jest/globals';
import { buildFingerprint } from '../../../src/discover/fingerprint.js';
import { buildCatalog } from '../../../src/probe/sobjectCatalog.js';
import type { IntelContext } from '../../../src/lib/wire.js';
import { mockSoql, mockTooling, mockRest, noopMetadata } from '../helpers/mocks.js';

const catalog = buildCatalog([
  { name: 'Account', label: 'Account', custom: false, queryable: true },
  { name: 'Lead', label: 'Lead', custom: false, queryable: true },
  { name: 'Opportunity', label: 'Opportunity', custom: false, queryable: true },
  { name: 'Case', label: 'Case', custom: false, queryable: true },
  { name: 'Claim__c', label: 'Claim', custom: true, queryable: true },
]);

function ctx(): IntelContext {
  return {
    soql: mockSoql([
      {
        test: (q) => q.includes('FROM RecordType'),
        records: [
          { SobjectType: 'Case', DeveloperName: 'Support', Name: 'Support Case' },
          { SobjectType: 'Case', DeveloperName: 'Billing', Name: 'Billing Case' },
        ],
      },
      {
        test: (q) => q.includes('FROM AppMenuItem'),
        records: [
          { Label: 'Sales', Name: 'standard__Sales' },
          { Label: 'Service Console', Name: 'standard__Service' },
        ],
      },
    ]),
    tooling: mockTooling([
      {
        test: (q) => q.includes('FROM InstalledSubscriberPackage'),
        records: [
          {
            SubscriberPackage: { Name: 'DocuSign', NamespacePrefix: 'dsfs' },
            SubscriberPackageVersion: { Name: '1.2' },
          },
        ],
      },
    ]),
    rest: mockRest([]),
    metadata: noopMetadata,
    orgInfo: { id: '00D', name: 'Org', type: 'EE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    apiVersion: '62.0',
    namespace: null,
  };
}

describe('buildFingerprint', () => {
  it('assembles packages, clouds, record types, apps, and object inventory', async () => {
    const fp = await buildFingerprint(ctx(), catalog, [
      { object: 'Case', field: 'Status', values: ['New', 'Closed'] },
    ]);

    expect(fp.version).toBe(1);
    expect(fp.installedPackages).toEqual([{ namespace: 'dsfs', name: 'DocuSign', version: '1.2' }]);
    expect(fp.clouds).toEqual(expect.arrayContaining(['Sales Cloud', 'Service Cloud']));
    expect(fp.recordTypes).toHaveLength(2);
    expect(fp.apps).toEqual(['Sales', 'Service Console']);
    expect(fp.objectInventory).toContain('Claim__c');
    expect(fp.statusPicklists).toEqual([{ object: 'Case', field: 'Status', values: ['New', 'Closed'] }]);
  });

  it('degrades to empty sections when queries are unavailable', async () => {
    const broken: IntelContext = {
      ...ctx(),
      soql: mockSoql([{ test: () => true, error: new Error('no access') }]),
      tooling: mockTooling([{ test: () => true, error: new Error('no access') }]),
    };
    const fp = await buildFingerprint(broken, catalog, []);
    expect(fp.installedPackages).toEqual([]);
    expect(fp.recordTypes).toEqual([]);
    expect(fp.apps).toEqual([]);
    // clouds are still inferable from the catalog alone
    expect(fp.clouds).toContain('Sales Cloud');
  });
});
