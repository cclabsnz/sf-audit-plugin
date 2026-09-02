import { jest } from '@jest/globals';
import { resolveIntegrationAccounts } from '../../../../src/checks/support/integrationAccounts.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  users?: unknown[];
  usersThrow?: boolean;
  jobs?: unknown[];
  jobsThrow?: boolean;
  extraUsers?: unknown[];
  logins?: unknown[];
  loginsThrow?: boolean;
}

export function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM AsyncApexJob')) {
      if (opts.jobsThrow) throw new Error('no access');
      return opts.jobs ?? [];
    }
    if (soql.includes('FROM LoginHistory')) {
      if (opts.loginsThrow) throw new Error('no access');
      return opts.logins ?? [];
    }
    if (soql.includes('FROM User') && soql.includes('Id IN')) {
      return opts.extraUsers ?? [];
    }
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

describe('resolveIntegrationAccounts — platform signals', () => {
  it('classifies a scheduled-job owner the username heuristic would miss', async () => {
    const ctx = makeCtx({
      users: [],
      jobs: [{ CreatedById: '005z' }],
      extraUsers: [
        {
          Id: '005z',
          Username: 'nightly@acme.com',
          Profile: { Name: 'Min Access', UserLicense: { Name: 'Salesforce' } },
          LastLoginDate: '2026-08-01T00:00:00.000Z',
          CreatedDate: '2020-01-01T00:00:00.000Z',
        },
      ],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts.map((a) => a.id)).toEqual(['005z']);
    expect(r.accounts[0].signals).toEqual(['scheduled-job-owner']);
  });

  it('merges a platform signal onto an account the candidate query already returned', async () => {
    const ctx = makeCtx({
      users: [
        {
          Id: '005a',
          Username: 'svc.api@acme.com',
          Profile: { Name: 'Integration', UserLicense: { Name: 'Salesforce' } },
          LastLoginDate: null,
          CreatedDate: '2020-01-01T00:00:00.000Z',
        },
      ],
      jobs: [{ CreatedById: '005a' }],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts).toHaveLength(1);
    expect(r.accounts[0].signals).toEqual(
      expect.arrayContaining(['username-pattern', 'never-logged-in', 'scheduled-job-owner']),
    );
  });

  it('degrades the job-owner signal without losing the other accounts', async () => {
    const ctx = makeCtx({
      users: [
        {
          Id: '005a',
          Username: 'svc.api@acme.com',
          Profile: { Name: 'Integration', UserLicense: { Name: 'Salesforce' } },
          LastLoginDate: null,
          CreatedDate: '2020-01-01T00:00:00.000Z',
        },
      ],
      jobsThrow: true,
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.degraded).toContain('scheduled-job-owner');
    expect(r.accounts).toHaveLength(1);
    expect(r.unavailable).toBe(false);
  });

  // connected-app-run-as: the live-org gate confirming which object exposes a connected app's
  // run-as user is not closed (this project forbids running against a real org), so the signal
  // is not implemented. It must always be disclosed as degraded rather than silently absent.
  it('always discloses connected-app-run-as as degraded (unimplemented pending live-org gate)', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ users: [] }));
    expect(r.degraded).toContain('connected-app-run-as');
  });
});

describe('resolveIntegrationAccounts — api-only-login', () => {
  const svc = {
    Id: '005a', Username: 'svc.api@acme.com',
    Profile: { Name: 'Integration', UserLicense: { Name: 'Salesforce' } },
    LastLoginDate: '2026-08-01T00:00:00.000Z', CreatedDate: '2020-01-01T00:00:00.000Z',
  };

  it('flags an account whose only logins are API logins', async () => {
    const ctx = makeCtx({
      users: [svc],
      logins: [{ UserId: '005a', Application: 'Data Loader Bulk', ApiType: 'SOAP Partner', logins: 12 }],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts[0].signals).toContain('api-only-login');
  });

  it('does not flag an account with any browser login', async () => {
    const ctx = makeCtx({
      users: [svc],
      logins: [
        { UserId: '005a', Application: 'Data Loader Bulk', ApiType: 'SOAP Partner', logins: 12 },
        { UserId: '005a', Application: 'Browser', ApiType: null, logins: 1 },
      ],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts[0].signals).not.toContain('api-only-login');
  });

  it('degrades the signal when LoginHistory is unreadable, keeping the account', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ users: [svc], loginsThrow: true }));
    expect(r.degraded).toContain('api-only-login');
    expect(r.accounts).toHaveLength(1);
    expect(r.accounts[0].signals).not.toContain('api-only-login');
  });

  // M3: `Application` is a free-text client name. An unanchored /api/ matches the "api" inside
  // "Rapid7 Insight", which would stamp api-only-login on a plainly interactive login.
  it('does not treat a connected app whose name merely contains "api" as an API login', async () => {
    const ctx = makeCtx({
      users: [svc],
      logins: [{ UserId: '005a', Application: 'Rapid7 Insight', ApiType: null, logins: 3 }],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts[0].signals).not.toContain('api-only-login');
  });

  it('still recognises a genuine API client name', async () => {
    const ctx = makeCtx({
      users: [svc],
      logins: [{ UserId: '005a', Application: 'Data Loader Bulk', ApiType: null, logins: 3 }],
    });
    const r = await resolveIntegrationAccounts(ctx);
    expect(r.accounts[0].signals).toContain('api-only-login');
  });
});

describe('resolveIntegrationAccounts — truncation and memoisation', () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => user({
    Id: `005x${String(i).padStart(11, '0')}`, Username: `integration${i}@acme.com`,
  }));

  it('is not truncated when the candidate query returns fewer rows than its limit', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ users: many(3) }));
    expect(r.truncated).toBe(false);
  });

  // SBS-ACS-007 asks for ALL non-human identities. A list capped at the query limit that reads as
  // complete is the wrong answer to that control, so the cap has to surface.
  it('reports truncation when the candidate query returns its full row limit', async () => {
    const r = await resolveIntegrationAccounts(makeCtx({ users: many(200) }));
    expect(r.truncated).toBe(true);
  });

  it('resolves once per context, so two checks do not each pay for the LoginHistory aggregate', async () => {
    const ctx = makeCtx({ users: [user()] });
    const first = await resolveIntegrationAccounts(ctx);
    const second = await resolveIntegrationAccounts(ctx);
    expect(second).toBe(first);
    const loginQueries = ((ctx.soql.queryAll as unknown) as jest.Mock).mock.calls
      .map((c) => c[0] as string)
      .filter((s) => s.includes('FROM LoginHistory'));
    expect(loginQueries).toHaveLength(1);
  });

  it('resolves independently for a different context', async () => {
    const a = await resolveIntegrationAccounts(makeCtx({ users: [user()] }));
    const b = await resolveIntegrationAccounts(makeCtx({ users: [] }));
    expect(a.accounts).toHaveLength(1);
    expect(b.accounts).toHaveLength(0);
  });
});
