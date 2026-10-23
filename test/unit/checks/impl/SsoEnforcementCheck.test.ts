import { jest } from '@jest/globals';
import { SsoEnforcementCheck } from '../../../../src/checks/impl/SsoEnforcementCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(logins: unknown[] | Error, users: unknown[] = []): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        if (/FROM LoginHistory/.test(q)) return logins instanceof Error ? Promise.reject(logins) : Promise.resolve(logins);
        return Promise.resolve(users);
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

const login = (UserId: string) => ({ Id: `0Ya${UserId}`, UserId, LoginType: 'Username-Password', LoginTime: '2026-10-01T00:00:00Z' });

describe('SsoEnforcementCheck', () => {
  const check = new SsoEnforcementCheck();

  it('never asks LoginHistory for Username, which it does not have', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[0][0] as string;
    expect(q).toMatch(/SELECT Id, UserId, LoginType, LoginTime\s+FROM LoginHistory/);
  });

  it('resolves usernames from User for the logins it found', async () => {
    const ctx = makeCtx([login('005A'), login('005A')], [{ Id: '005A', Username: 'a@x.com' }]);
    const r = await check.run(ctx);
    const lookup = (ctx.soql.queryAll as any).mock.calls[1][0] as string;
    expect(lookup).toBe("SELECT Id, Username FROM User WHERE Id IN ('005A')");
    expect(r.findings[0].affectedItems?.[0].label).toBe('a@x.com');
  });

  it('is inconclusive and quotes the error when LoginHistory cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS: LoginHistory')));
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].detail).toContain('INSUFFICIENT_ACCESS: LoginHistory');
  });
});
