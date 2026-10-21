import { jest } from '@jest/globals';
import { InternalUserMfaCheck } from '../../../../src/checks/impl/InternalUserMfaCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const user = (i: number) => ({ Id: `005xx00000000${i}`, Username: `u${i}@example.com`, Profile: { Name: 'Standard User' }, LastLoginDate: null });

function makeCtx(opts: { users?: unknown[]; mfaAssigned?: string[]; mfaThrows?: Error; mfaFieldPresent?: boolean }): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(async () => opts.users ?? []),
      query: (jest.fn() as any).mockImplementation(async () => {
        if (opts.mfaThrows) throw opts.mfaThrows;
        return { records: (opts.mfaAssigned ?? []).map((AssigneeId) => ({ AssigneeId })) };
      }),
    } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {
      get: (jest.fn() as any).mockImplementation(async () => ({
        fields: [{ name: 'Id' }, ...(opts.mfaFieldPresent === false ? [] : [{ name: 'PermissionsForceTwoFactor' }])],
      })),
    } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('InternalUserMfaCheck', () => {
  const check = new InternalUserMfaCheck();

  it('passes when every internal user holds the MFA permission', async () => {
    const r = await check.run(makeCtx({ users: [user(1), user(2)], mfaAssigned: [user(1).Id, user(2).Id] }));
    expect(r.findings[0].id).toBe('internal-user-mfa-all-enforced');
    expect(r.findings[0].passed).toBe(true);
  });

  it('names the users without the permission', async () => {
    const r = await check.run(makeCtx({ users: [user(1), user(2)], mfaAssigned: [user(1).Id] }));
    const f = r.findings[0];
    expect(f.id).toBe('internal-user-mfa-gaps');
    expect(f.affectedItems!.map((a) => a.label)).toEqual(['u2@example.com']);
  });

  it('is not assessed, never a gap or a pass, when the org has no MFA permission field (MN-051)', async () => {
    const ctx = makeCtx({ users: [user(1)], mfaFieldPresent: false });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('internal-user-mfa-not-available');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].notAssessed).toBe(true);
    expect(r.findings[0].passed).toBeFalsy();
    expect((ctx.soql.query as any).mock.calls).toHaveLength(0);
  });

  it('quotes the org error when the assignment query fails', async () => {
    const r = await check.run(makeCtx({ users: [user(1)], mfaThrows: new Error('INSUFFICIENT_ACCESS: nope') }));
    const f = r.findings[0];
    expect(f.id).toBe('internal-user-mfa-inaccessible');
    expect(f.inconclusive).toBe(true);
    expect(f.detail).toContain('INSUFFICIENT_ACCESS: nope');
  });
});
