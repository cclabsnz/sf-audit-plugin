import { describe, it, expect } from '@jest/globals';
import {
  buildCatalog,
  historyObjectName,
  customBusinessObjects,
  KEY_STANDARD_OBJECTS,
} from '../../../src/probe/sobjectCatalog.js';

describe('sobjectCatalog', () => {
  it('historyObjectName handles standard and custom objects', () => {
    expect(historyObjectName('Account', false)).toBe('AccountHistory');
    expect(historyObjectName('Case', false)).toBe('CaseHistory');
    expect(historyObjectName('Claim__c', true)).toBe('Claim__History');
  });

  it('buildCatalog exposes presence and queryability', () => {
    const cat = buildCatalog([
      { name: 'Account', label: 'Account', custom: false, queryable: true },
      { name: 'Secret__c', label: 'Secret', custom: true, queryable: false },
    ]);
    expect(cat.has('Account')).toBe(true);
    expect(cat.has('Nope')).toBe(false);
    expect(cat.isQueryable('Account')).toBe(true);
    expect(cat.isQueryable('Secret__c')).toBe(false);
    expect(cat.isQueryable('Nope')).toBe(false);
  });

  it('customBusinessObjects keeps queryable __c and drops companion tables', () => {
    const cat = buildCatalog([
      { name: 'Account', label: 'Account', custom: false, queryable: true },
      { name: 'Claim__c', label: 'Claim', custom: true, queryable: true },
      { name: 'Claim__History', label: 'Claim History', custom: true, queryable: true },
      { name: 'Claim__Share', label: 'Claim Share', custom: true, queryable: true },
      { name: 'Hidden__c', label: 'Hidden', custom: true, queryable: false },
    ]);
    const names = customBusinessObjects(cat).map((s) => s.name);
    expect(names).toEqual(['Claim__c']);
  });

  it('KEY_STANDARD_OBJECTS includes the core process objects', () => {
    expect(KEY_STANDARD_OBJECTS).toEqual(expect.arrayContaining(['Account', 'Case', 'Opportunity']));
  });
});
