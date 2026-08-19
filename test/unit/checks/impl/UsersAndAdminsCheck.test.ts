import { jest } from '@jest/globals';
import { UsersAndAdminsCheck } from '../../../../src/checks/impl/UsersAndAdminsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type Perms = Partial<{
  ModifyAllData: boolean; ViewAllData: boolean; ManageUsers: boolean;
  CustomizeApplication: boolean; AuthorApex: boolean;
}>;

/** One PermissionSetAssignment row: user `id` granted `perms` via permission set `via`. */
const row = (id: string, perms: Perms, via = 'Admin_PS', ownedByProfile = false) => ({
  Assignee: { Id: id, Username: `${id}@x.com`, Name: id, Profile: { Name: 'System Administrator' } },
  PermissionSet: {
    Name: via,
    IsOwnedByProfile: ownedByProfile,
    PermissionsModifyAllData: perms.ModifyAllData ?? false,
    PermissionsViewAllData: perms.ViewAllData ?? false,
    PermissionsManageUsers: perms.ManageUsers ?? false,
    PermissionsCustomizeApplication: perms.CustomizeApplication ?? false,
    PermissionsAuthorApex: perms.AuthorApex ?? false,
  },
});

function makeCtx(rows: unknown[], totalActiveUsers = 50): AuditContext {
  return {
    soql: {
      queryAll: jest.fn(),
      query: (jest.fn() as any).mockImplementation((s: string) =>
        /COUNT\(\)/i.test(s)
          ? Promise.resolve({ totalSize: totalActiveUsers, records: [] })
          : Promise.resolve({ totalSize: rows.length, records: rows }),
      ),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

/** n distinct users each holding the given permissions. */
const users = (n: number, perms: Perms) =>
  Array.from({ length: n }, (_, i) => row(`u${i}`, perms));

describe('UsersAndAdminsCheck', () => {
  const check = new UsersAndAdminsCheck();

  it('always reports the Modify All / View All population, even at zero', async () => {
    const r = await check.run(makeCtx([]));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain('users-modify-all-data');
    expect(ids).toContain('users-view-all-data');
    expect(r.findings.find((f) => f.id === 'users-modify-all-data')!.riskLevel).toBe('LOW');
  });

  it('returns org metrics alongside the findings', async () => {
    const r = await check.run(makeCtx(users(2, { ModifyAllData: true }), 137));
    expect(r.metrics).toMatchObject({
      totalActiveUsers: 137,
      modifyAllDataUsersCount: 2,
      viewAllDataUsersCount: 0,
    });
  });

  // Severity tracks how many people hold the permission, so the boundaries matter.
  it.each([
    [3, 'LOW'], [4, 'HIGH'], [5, 'HIGH'], [6, 'CRITICAL'],
  ])('rates %i Modify All Data users as %s', async (n, expected) => {
    const r = await check.run(makeCtx(users(n, { ModifyAllData: true })));
    expect(r.findings.find((f) => f.id === 'users-modify-all-data')!.riskLevel).toBe(expected);
  });

  it.each([
    [5, 'LOW'], [6, 'MEDIUM'], [10, 'MEDIUM'], [11, 'HIGH'],
  ])('rates %i View All Data users as %s', async (n, expected) => {
    const r = await check.run(makeCtx(users(n, { ViewAllData: true })));
    expect(r.findings.find((f) => f.id === 'users-view-all-data')!.riskLevel).toBe(expected);
  });

  it('counts a user once even when several permission sets grant the same permission', async () => {
    const r = await check.run(makeCtx([
      row('same', { ModifyAllData: true }, 'PS_One'),
      row('same', { ModifyAllData: true }, 'PS_Two'),
      row('same', { ModifyAllData: true }, 'PS_Three'),
    ]));
    const f = r.findings.find((x) => x.id === 'users-modify-all-data')!;
    expect(f.title).toContain('1 user(s)');
    // LOW, because it is one person — not three.
    expect(f.riskLevel).toBe('LOW');
    // Every grant path is still listed, so the reader can see where it comes from.
    expect(f.affectedItems).toHaveLength(3);
  });

  it('flags the super-admin combination only when one user holds all three', async () => {
    const all = await check.run(makeCtx([
      row('boss', { ModifyAllData: true, ViewAllData: true, ManageUsers: true }),
    ]));
    const f = all.findings.find((x) => x.id === 'users-super-admin-combo');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');

    const twoOfThree = await check.run(makeCtx([
      row('boss', { ModifyAllData: true, ViewAllData: true }),
    ]));
    expect(twoOfThree.findings.some((x) => x.id === 'users-super-admin-combo')).toBe(false);
  });

  it('does not manufacture a super-admin from three separate people', async () => {
    const r = await check.run(makeCtx([
      row('a', { ModifyAllData: true }),
      row('b', { ViewAllData: true }),
      row('c', { ManageUsers: true }),
    ]));
    expect(r.findings.some((x) => x.id === 'users-super-admin-combo')).toBe(false);
  });

  it('assembles the combination across different permission sets for one user', async () => {
    const r = await check.run(makeCtx([
      row('boss', { ModifyAllData: true }, 'PS_Data'),
      row('boss', { ViewAllData: true }, 'PS_Read'),
      row('boss', { ManageUsers: true }, 'PS_Ident'),
    ]));
    expect(r.findings.some((x) => x.id === 'users-super-admin-combo')).toBe(true);
  });

  it('reports Customize Application and Author Apex only above their thresholds', async () => {
    const quiet = await check.run(makeCtx([
      ...users(5, { CustomizeApplication: true }),
      ...users(3, { AuthorApex: true }),
    ]));
    expect(quiet.findings.some((f) => f.id === 'users-customize-application')).toBe(false);
    expect(quiet.findings.some((f) => f.id === 'users-author-apex')).toBe(false);

    const loud = await check.run(makeCtx([
      ...Array.from({ length: 6 }, (_, i) => row(`c${i}`, { CustomizeApplication: true })),
      ...Array.from({ length: 4 }, (_, i) => row(`a${i}`, { AuthorApex: true })),
    ]));
    expect(loud.findings.some((f) => f.id === 'users-customize-application')).toBe(true);
    expect(loud.findings.some((f) => f.id === 'users-author-apex')).toBe(true);
  });

  it('names the grant path so a reader can act on it', async () => {
    const viaPs = await check.run(makeCtx([row('u', { ModifyAllData: true }, 'Data_Admin_PS', false)]));
    expect(viaPs.findings.find((f) => f.id === 'users-modify-all-data')!.affectedItems?.[0].note)
      .toBe('via: Data_Admin_PS');

    const viaProfile = await check.run(makeCtx([row('u', { ModifyAllData: true }, 'X', true)]));
    expect(viaProfile.findings.find((f) => f.id === 'users-modify-all-data')!.affectedItems?.[0].note)
      .toBe('via: Profile');
  });

  it('excludes frozen and inactive users in the query itself', async () => {
    const seen: string[] = [];
    const ctx = makeCtx([]);
    (ctx.soql.query as any).mockImplementation((s: string) => {
      seen.push(s);
      return Promise.resolve({ totalSize: 0, records: [] });
    });
    await check.run(ctx);
    const psaQuery = seen.find((s) => /FROM PermissionSetAssignment/i.test(s))!;
    expect(psaQuery).toMatch(/Assignee\.IsActive\s*=\s*true/i);
    expect(psaQuery).toMatch(/IsFrozen\s*=\s*true/i);
  });
});
