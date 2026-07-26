import { describe, it, expect } from '@jest/globals';
import { classifyQueryError } from '../../../src/probe/query.js';

describe('classifyQueryError', () => {
  it('detects absent objects', () => {
    expect(classifyQueryError(new Error("sObject type 'ProcessInstance' is not supported"))).toBe('not-present');
    expect(classifyQueryError(new Error('INVALID_TYPE: ...'))).toBe('not-present');
    expect(classifyQueryError(new Error('The requested resource does not exist'))).toBe('not-present');
  });

  it('detects permission failures', () => {
    expect(classifyQueryError(new Error('INSUFFICIENT_ACCESS'))).toBe('no-access');
    expect(classifyQueryError(new Error('field is not readable'))).toBe('no-access');
  });

  it('falls back to unknown', () => {
    expect(classifyQueryError(new Error('some transient network blip'))).toBe('unknown');
  });
});
