import { jest } from '@jest/globals';
import { PrivilegedAccessCheck } from '../../../../src/checks/impl/PrivilegedAccessCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

// Build a PermissionSetAssignment row. `perms` is the set of Permissions* fields that are true.
function psaRow(username: string, profile: string, perms: string[], name = username) {
  const ps: Record<string, boolean> = {};
  for (const p of perms) ps[`Permissions${p}`] = true;
  return { AssigneeId: username, Assignee: { Username: username, Name: name, Profile: { Name: profile } }, PermissionSet: ps };
}

function makeCtx(rows: unknown[] | Error): AuditContext {
  const cache: any = {};
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation(async () => {
        if (rows instanceof Error) throw rows;
        return rows;
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache,
  } as any;
}

describe('PrivilegedAccessCheck', () => {
  const check = new PrivilegedAccessCheck();

  it('flags a shadow admin (Modify All Data on a non-admin profile) as CRITICAL', async () => {
    const ctx = makeCtx([psaRow('dev@x.com', 'Developer', ['ModifyAllData'])]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'privileged-access-shadow-admins');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toBe('dev@x.com');
  });

  it('treats Manage Users + Assign Permission Sets as admin-equivalent', async () => {
    const ctx = makeCtx([psaRow('ops@x.com', 'Ops', ['ManageUsers', 'AssignPermissionSets'])]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'privileged-access-shadow-admins')).toBe(true);
  });

  it('does NOT flag Modify All Data held on the System Administrator profile', async () => {
    const ctx = makeCtx([psaRow('admin@x.com', 'System Administrator', ['ModifyAllData'])]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'privileged-access-no-shadow-admins' && f.passed)).toBe(true);
  });

  it('unions effective perms across multiple PSA rows and populates the cache', async () => {
    const ctx = makeCtx([
      psaRow('u@x.com', 'Sales', ['ManageUsers']),
      psaRow('u@x.com', 'Sales', ['AssignPermissionSets']),
    ]);
    await check.run(ctx);
    const grant = (ctx.cache.effectivePermissions ?? []).find((g) => g.username === 'u@x.com');
    expect(grant).toBeDefined();
    expect(new Set(grant!.perms)).toEqual(new Set(['ManageUsers', 'AssignPermissionSets']));
  });

  it('is inconclusive when the query is not accessible', async () => {
    const ctx = makeCtx(Object.assign(new Error('no access'), { errorCode: 'INSUFFICIENT_ACCESS' }));
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
    expect(ctx.cache.effectivePermissions).toBeUndefined();
  });
});
