import { jest } from '@jest/globals';
import { resolveIntegrationAccounts } from '../../../../src/checks/support/integrationAccounts.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  users?: unknown[];
  usersThrow?: boolean;
}

export function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM User')) {
      if (opts.usersThrow) throw new Error('no access');
      return opts.users ?? [];
    }
    return [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const user = (over: Record<string, unknown> = {}) => ({
  Id: '005a',
  Username: 'svc.api@acme.com',
  Profile: { Name: 'Integration', UserLicense: { Name: 'Salesforce' } },
  LastLoginDate: '2026-08-01T00:00:00.000Z',
  CreatedDate: '2020-01-01T00:00:00.000Z',
  ...over,
});

describe('resolveIntegrationAccounts', () => {
  it('classifies an account matching a service username pattern', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ users: [user()] }));
    expect(r.accounts).toHaveLength(1);
    expect(r.accounts[0].signals).toContain('username-pattern');
    expect(r.accounts[0].username).toBe('svc.api@acme.com');
  });

  it('classifies an account on the Salesforce Integration license', async () => {
    const u = user({ Username: 'nightly@acme.com', Profile: { Name: 'Min Access', UserLicense: { Name: 'Salesforce Integration' } } });
    const r = await resolveIntegrationAccounts(makeCtx({ users: [u] }));
    expect(r.accounts[0].signals).toEqual(['integration-license']);
  });

  it('classifies an account that has never logged in', async () => {
    const u = user({ Username: 'nightly@acme.com', LastLoginDate: null });
    const r = await resolveIntegrationAccounts(makeCtx({ users: [u] }));
    expect(r.accounts[0].signals).toContain('never-logged-in');
  });

  it('accumulates every matching signal on one account', async () => {
    const u = user({ LastLoginDate: null });
    const r = await resolveIntegrationAccounts(makeCtx({ users: [u] }));
    expect(r.accounts[0].signals).toEqual(expect.arrayContaining(['username-pattern', 'never-logged-in']));
  });

  it('reports unavailable when the candidate query fails', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ usersThrow: true }));
    expect(r.unavailable).toBe(true);
    expect(r.accounts).toEqual([]);
  });

  it('includes escaped underscores in the SOQL query to match literal delimiters', async () => {
    const ctx = makeCtx({ users: [] });
    await resolveIntegrationAccounts(ctx);
    const soql = (ctx.soql.queryAll as jest.Mock).mock.calls[0][0];
    expect(soql).toContain("%\\_api\\_%");
    expect(soql).toContain("%\\_svc\\_%");
  });

  it('excludes accounts that match no intrinsic signals', async () => {
    const u = user({ Username: 'kapil@acme.com' });
    const r = await resolveIntegrationAccounts(makeCtx({ users: [u] }));
    expect(r.accounts).toEqual([]);
  });
});
