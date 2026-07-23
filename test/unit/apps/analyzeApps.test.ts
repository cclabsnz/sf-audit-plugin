import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeApps } from '../../../src/apps/analyzeApps.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const csv = fs.readFileSync(path.join(here, '__fixtures__/restapi-sample.csv'), 'utf-8');

function soql() {
  return {
    query: async () => ({ totalSize: 0, done: true, records: [] }),
    queryAll: async (q: string) => {
      if (q.includes('AppMenuItem')) return [{ ApplicationId: '0H4app0000001AAA', Label: 'IMMS NIS Integration' }];
      if (q.includes('PermissionSetAssignment')) return [{ AssigneeId: '005INT00000001', PermissionSetId: '0PS1' }];
      if (q.includes('ObjectPermissions'))
        return [
          { ParentId: '0PS1', SobjectType: 'Account', PermissionsRead: true, PermissionsCreate: true, PermissionsEdit: true, PermissionsDelete: true },
          { ParentId: '0PS1', SobjectType: 'Case', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
        ];
      return [];
    },
  } as any;
}

describe('analyzeApps (golden fixture)', () => {
  it('produces a least-privilege finding for the resolved app', async () => {
    const [f] = await analyzeApps(csv, soql(), { since: 30, soakDays: 7 });
    expect(f.app.name).toBe('IMMS NIS Integration');
    expect(f.used.objects.map((o) => o.object)).toEqual(['Account']);
    expect(f.overGrant.unusedObjects).toEqual(['Case']);         // granted Case, never used
    expect(f.overGrant.scopeDowngrade).toBeNull();               // scope not queried here -> null scope
    expect(f.recommendation.permissionSet.objectPermissions[0].object).toBe('Account');
  });
});
