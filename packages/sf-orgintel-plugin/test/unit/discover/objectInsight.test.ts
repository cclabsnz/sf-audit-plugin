import { describe, it, expect } from '@jest/globals';
import { extractInsight, detectStatusField, type ObjectDescribe } from '../../../src/discover/objectInsight.js';

const caseDescribe: ObjectDescribe = {
  name: 'Case',
  label: 'Case',
  custom: false,
  fields: [
    {
      name: 'Status',
      label: 'Status',
      type: 'picklist',
      picklistValues: [
        { value: 'New', active: true },
        { value: 'Working', active: true },
        { value: 'Escalated', active: true },
        { value: 'Closed', active: true },
        { value: 'Archived', active: false },
      ],
    },
    { name: 'Subject', label: 'Subject', type: 'string' },
  ],
  childRelationships: [
    { childSObject: 'CaseComment', field: 'ParentId' },
    { childSObject: 'WorkOrder', field: 'CaseId' },
    { childSObject: 'CaseHistory', field: 'CaseId' }, // system -> excluded
    { childSObject: 'CaseShare', field: 'ParentId' }, // system -> excluded
    { childSObject: 'AttachedContentDocument', field: 'X' }, // system -> excluded
  ],
};

describe('objectInsight', () => {
  it('detects a name-matched status field with active values in order', () => {
    const insight = extractInsight(caseDescribe);
    expect(insight.statusField).not.toBeNull();
    expect(insight.statusField!.field).toBe('Status');
    expect(insight.statusField!.matchedByName).toBe(true);
    expect(insight.statusField!.values).toEqual(['New', 'Working', 'Escalated', 'Closed']); // inactive dropped
  });

  it('counts inbound references excluding system companion objects', () => {
    const insight = extractInsight(caseDescribe);
    expect(insight.inboundReferences).toBe(2); // CaseComment + WorkOrder
  });

  it('infers a lifecycle field when no name matches', () => {
    const sf = detectStatusField([
      {
        name: 'Phase__c', // matches pattern actually — use a non-matching name below
        label: 'X',
        type: 'picklist',
        picklistValues: [{ value: 'Qualified' }, { value: 'Won' }, { value: 'Lost' }],
      },
    ]);
    expect(sf?.field).toBe('Phase__c');

    const inferred = detectStatusField([
      {
        name: 'Disposition__c',
        label: 'Disposition',
        type: 'picklist',
        picklistValues: [{ value: 'Open' }, { value: 'Approved' }, { value: 'Rejected' }],
      },
    ]);
    expect(inferred).not.toBeNull();
    expect(inferred!.matchedByName).toBe(false);
  });

  it('returns null when no picklist looks like a lifecycle', () => {
    expect(
      detectStatusField([
        { name: 'Color__c', label: 'Color', type: 'picklist', picklistValues: [{ value: 'Red' }, { value: 'Blue' }] },
      ]),
    ).toBeNull();
  });
});
