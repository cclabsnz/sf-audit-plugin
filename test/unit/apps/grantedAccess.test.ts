import { computeGranted } from '../../../src/apps/grantedAccess.js';

function soqlReturning(psa: any[], perms: any[]) {
  return {
    query: async () => ({ totalSize: 0, done: true, records: [] }),
    queryAll: async (soql: string) => {
      if (soql.includes('PermissionSetAssignment')) return psa;
      if (soql.includes('ObjectPermissions')) return perms;
      return [];
    },
  } as any;
}

describe('computeGranted', () => {
  it('folds ObjectPermissions into per-object verbs for the run-as users', async () => {
    const soql = soqlReturning(
      [{ AssigneeId: '005U1', PermissionSetId: '0PS1' }],
      [
        { ParentId: '0PS1', SobjectType: 'Account', PermissionsRead: true, PermissionsCreate: true, PermissionsEdit: false, PermissionsDelete: false },
        { ParentId: '0PS1', SobjectType: 'Case', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
      ],
    );
    const g = await computeGranted('0H4app0000001', ['005U1'], soql, 'full');
    const acct = g.objects.find((o) => o.object === 'Account')!;
    expect(acct.verbs.sort()).toEqual(['read', 'write']);
    expect(g.objects.map((o) => o.object).sort()).toEqual(['Account', 'Case']);
    expect(g.multiUserInteractive).toBe(false);
    expect(g.scope).toBe('full');
  });

  it('flags multi-user interactive apps (many run-as users)', async () => {
    const soql = soqlReturning([], []);
    const g = await computeGranted('0H4app0000001', ['a', 'b', 'c', 'd', 'e'], soql, null);
    expect(g.multiUserInteractive).toBe(true);
  });
});
