import { jest } from '@jest/globals';
import { InactiveUsersCheck } from '../../../../src/checks/impl/InactiveUsersCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(count: number): AuditContext {
  return {
    soql: {
      query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: count }] }),
      queryAll: (jest.fn() as any).mockResolvedValue([]),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

describe('InactiveUsersCheck', () => {
  const check = new InactiveUsersCheck();

  // expr0 is reserved: an explicit `COUNT(Id) expr0` alias is rejected by the org, while an
  // unaliased COUNT(Id) still returns its value as expr0.
  it('counts without the reserved expr0 alias and reads the implicit expr0', async () => {
    const ctx = makeCtx(3);
    const r = await check.run(ctx);
    const q = (ctx.soql.query as any).mock.calls[0][0] as string;
    expect(q).toMatch(/^SELECT COUNT\(Id\) FROM User WHERE/);
    expect(q).not.toMatch(/expr0/);
    expect(r.metrics?.inactiveUsers90d).toBe(3);
  });

  it('passes when the count is zero', async () => {
    const r = await check.run(makeCtx(0));
    expect(r.findings[0].passed).toBe(true);
  });
});
