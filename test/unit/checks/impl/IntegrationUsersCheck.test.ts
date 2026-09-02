import { jest } from '@jest/globals';
import { IntegrationUsersCheck } from '../../../../src/checks/impl/IntegrationUsersCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  candidates?: unknown[];
  candidatesThrow?: boolean;
  broadPerms?: unknown[];
  jobOwners?: unknown[];
  apiOnlyRows?: unknown[];
  supplementaryUsers?: unknown[];
}

function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (sql: string) => {
    // Route the resolver's additional queries independently of the primary candidate query,
    // so opts.candidates keeps answering the resolver's candidate `FROM User` query specifically.
    if (/FROM AsyncApexJob/.test(sql)) return opts.jobOwners ?? [];
    if (/FROM LoginHistory/.test(sql)) return opts.apiOnlyRows ?? [];
    if (/FROM User WHERE IsActive = true AND Id IN/.test(sql)) return opts.supplementaryUsers ?? [];
    if (opts.candidatesThrow) throw new Error('INSUFFICIENT_ACCESS: no access to User');
    return opts.candidates ?? [];
  });
  const query = jest.fn() as any;
  query.mockImplementation(async () => ({ records: opts.broadPerms ?? [] }));
  return {
    soql: { query, queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const svcUser = { Id: '005a', Username: 'svc.api@acme.com', Profile: { Name: 'Integration' }, LastLoginDate: null };
const perm = (over: Record<string, unknown> = {}) => ({
  Assignee: { Id: '005a', Username: 'svc.api@acme.com' },
  PermissionSet: { Name: 'PS', PermissionsModifyAllData: false, PermissionsViewAllData: false, ...over },
});

describe('IntegrationUsersCheck (characterization)', () => {
  const check = new IntegrationUsersCheck();

  it('passes with integration-users-none when no candidates are found', async () => {
    const r = await check.run(makeCtx({ candidates: [] }));
    expect(r.findings.map((f) => f.id)).toEqual(['integration-users-none']);
    expect(r.findings[0].passed).toBe(true);
  });

  it('emits an INFO inventory finding listing each candidate', async () => {
    const r = await check.run(makeCtx({ candidates: [svcUser] }));
    const inv = r.findings.find((f) => f.id === 'integration-users-inventory')!;
    expect(inv.riskLevel).toBe('INFO');
    expect(inv.affectedItems!.map((i) => i.label)).toEqual(['svc.api@acme.com']);
  });

  it('rates Modify All Data HIGH', async () => {
    const r = await check.run(
      makeCtx({ candidates: [svcUser], broadPerms: [perm({ PermissionsModifyAllData: true })] }),
    );
    expect(r.findings.find((f) => f.id === 'integration-users-broad-permissions')!.riskLevel).toBe('HIGH');
  });

  it('rates View All Data alone MEDIUM', async () => {
    const r = await check.run(
      makeCtx({ candidates: [svcUser], broadPerms: [perm({ PermissionsViewAllData: true })] }),
    );
    expect(r.findings.find((f) => f.id === 'integration-users-broad-permissions')!.riskLevel).toBe('MEDIUM');
  });

  it('names the grant path on each broad-permission item', async () => {
    const r = await check.run(
      makeCtx({ candidates: [svcUser], broadPerms: [perm({ PermissionsModifyAllData: true })] }),
    );
    const item = r.findings.find((f) => f.id === 'integration-users-broad-permissions')!.affectedItems![0];
    expect(item.note).toContain('PS');
  });

  it('emits no broad-permission finding when nothing broad is granted', async () => {
    const r = await check.run(makeCtx({ candidates: [svcUser], broadPerms: [] }));
    expect(r.findings.map((f) => f.id)).not.toContain('integration-users-broad-permissions');
  });
});

describe('IntegrationUsersCheck (post-refactor)', () => {
  const check = new IntegrationUsersCheck();

  it('inventories a licence-only account the old username heuristic would miss', async () => {
    const ctx = makeCtx({
      candidates: [{
        Id: '005z', Username: 'nightly@acme.com',
        Profile: { Name: 'Min Access', UserLicense: { Name: 'Salesforce Integration' } },
        LastLoginDate: '2026-08-01T00:00:00.000Z', CreatedDate: '2020-01-01T00:00:00.000Z',
      }],
    });
    const r = await check.run(ctx);
    const inv = r.findings.find((f) => f.id === 'integration-users-inventory')!;
    expect(inv.affectedItems!.map((i) => i.label)).toEqual(['nightly@acme.com']);
  });

  it('is inconclusive, not passed, when the resolver cannot query users', async () => {
    const r = await check.run(makeCtx({ candidatesThrow: true }));
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings.some((f) => f.passed)).toBe(false);
  });

  it('reports Modify All Data on a licence account with a non-service username that has logged in (R3)', async () => {
    // Under the pre-refactor Q2 (Assignee.LastLoginDate = null OR username-pattern), an account
    // with a real login history and a plain corporate username could never appear here, even
    // though the inventory above lists it by licence alone. Q2 must now see every resolved account.
    const ctx = makeCtx({
      candidates: [{
        Id: '005y', Username: 'jane.doe@acme.com',
        Profile: { Name: 'Min Access', UserLicense: { Name: 'Salesforce Integration' } },
        LastLoginDate: '2026-08-15T00:00:00.000Z', CreatedDate: '2019-01-01T00:00:00.000Z',
      }],
      broadPerms: [{
        Assignee: { Id: '005y', Username: 'jane.doe@acme.com' },
        PermissionSet: { Name: 'Data Sync', PermissionsModifyAllData: true, PermissionsViewAllData: false },
      }],
    });
    const r = await check.run(ctx);
    const broad = r.findings.find((f) => f.id === 'integration-users-broad-permissions');
    expect(broad).toBeDefined();
    expect(broad!.riskLevel).toBe('HIGH');
    expect(broad!.affectedItems!.map((i) => i.label)).toEqual(['jane.doe@acme.com']);
  });
});
