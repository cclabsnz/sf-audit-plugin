import { jest } from '@jest/globals';
import { MfaRegistrationCheck } from '../../../../src/checks/impl/MfaRegistrationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

describe('MfaRegistrationCheck', () => {
  it('counts active users without the reserved expr0 alias', async () => {
    const ctx = {
      soql: {
        query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: 0 }] }),
        queryAll: (jest.fn() as any).mockResolvedValue([]),
      },
      tooling: {},
      rest: {},
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
      cache: {},
    } as unknown as AuditContext;
    await new MfaRegistrationCheck().run(ctx);
    const q = (ctx.soql.query as any).mock.calls[0][0] as string;
    expect(q).toMatch(/^SELECT COUNT\(Id\) FROM User/);
    expect(q).not.toMatch(/expr0/);
  });
});
