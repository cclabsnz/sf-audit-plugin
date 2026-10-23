import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { fieldsOf, hasField, presentFields } from '../../../../src/checks/support/schema.js';

function ctxWith(get: (path: string) => Promise<unknown>): AuditContext {
  return { soql: {} as any, tooling: {} as any, rest: { get } as any, orgInfo: {} as any, cache: {} };
}

const describeOf = (...names: string[]) => Promise.resolve({ fields: names.map((name) => ({ name })) });

describe('schema support', () => {
  it('describes through the standard or Tooling API by path', async () => {
    const get = jest.fn((path: string) => describeOf(path.startsWith('/tooling') ? 'ToolingOnly' : 'StandardOnly'));
    const ctx = ctxWith(get as any);
    expect(await hasField(ctx, 'X', 'StandardOnly')).toBe(true);
    expect(await hasField(ctx, 'X', 'ToolingOnly', 'tooling')).toBe(true);
    expect(get).toHaveBeenCalledWith('/sobjects/X/describe');
    expect(get).toHaveBeenCalledWith('/tooling/sobjects/X/describe');
  });

  it('returns only the present fields, in the order asked', async () => {
    const ctx = ctxWith(() => describeOf('B', 'A'));
    expect(await presentFields(ctx, 'PermissionSet', ['A', 'Missing', 'B'])).toEqual(['A', 'B']);
  });

  it('describes each object once per audit', async () => {
    const get = jest.fn(() => describeOf('A'));
    const ctx = ctxWith(get as any);
    await Promise.all([fieldsOf(ctx, 'O'), fieldsOf(ctx, 'O'), hasField(ctx, 'O', 'A')]);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('treats an object this API does not serve as absent', async () => {
    const ctx = ctxWith(() => Promise.reject(Object.assign(new Error('The requested resource does not exist'), { errorCode: 'NOT_FOUND' })));
    expect(await fieldsOf(ctx, 'Nope')).toBeNull();
    expect(await presentFields(ctx, 'Nope', ['A'])).toEqual([]);
  });

  it('rethrows an access error rather than hiding it as absence', async () => {
    const ctx = ctxWith(() => Promise.reject(Object.assign(new Error('insufficient access'), { errorCode: 'INSUFFICIENT_ACCESS_RIGHTS' })));
    await expect(fieldsOf(ctx, 'O')).rejects.toThrow('insufficient access');
  });
});
