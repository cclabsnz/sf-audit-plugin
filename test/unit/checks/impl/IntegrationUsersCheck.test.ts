import { jest } from '@jest/globals';
import { IntegrationUsersCheck } from '../../../../src/checks/impl/IntegrationUsersCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  candidates?: unknown[];
  broadPerms?: unknown[];
}

function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => opts.candidates ?? []);
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
