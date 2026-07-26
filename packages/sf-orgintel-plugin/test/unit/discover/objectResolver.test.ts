import { describe, it, expect } from '@jest/globals';
import { resolverFromEntities } from '../../../src/discover/objectResolver.js';

const resolver = resolverFromEntities([
  { QualifiedApiName: 'Account', DurableId: 'Account', KeyPrefix: '001' },
  { QualifiedApiName: 'Claim__c', DurableId: '01I5x000000AbcDEAU', KeyPrefix: 'a0X' },
]);

describe('objectResolver', () => {
  it('resolves standard object API names directly', () => {
    expect(resolver.resolve('Account')).toBe('Account');
  });

  it('resolves custom object DurableId to API name', () => {
    expect(resolver.resolve('01I5x000000AbcDEAU')).toBe('Claim__c');
  });

  it('resolves a custom object record Id via key prefix', () => {
    expect(resolver.resolve('a0X5x000000ZzzzEAU')).toBe('Claim__c');
  });

  it('returns null for an unknown Id', () => {
    expect(resolver.resolve('zzz5x000000ZzzzEAU')).toBeNull();
  });
});
