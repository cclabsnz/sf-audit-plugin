import { buildFinding } from '../../../src/apps/leastPrivilege.js';
import type { AppUsage, GrantedAccess, ResolvedApp } from '../../../src/apps/types.js';

const app: ResolvedApp = { appId: '0H4app1', name: 'IMMS NIS Integration', category: 'Org-custom', confidence: 'resolved' };
const used: AppUsage = { appId: '0H4app1', objects: [{ object: 'Account', verbs: ['read'] }], requests: 100, rowsProcessed: 500, userIds: ['005U1'], soapOnly: false };
const granted: GrantedAccess = { appId: '0H4app1', scope: 'full', objects: [
  { object: 'Account', verbs: ['read', 'write', 'delete'] },
  { object: 'Case', verbs: ['read'] },
], runAsUsers: ['005U1'], multiUserInteractive: false };

describe('buildFinding', () => {
  it('reports unused objects, unused verbs, and a full->api scope downgrade', () => {
    const f = buildFinding(app, used, granted, { since: 30, attributionRatePct: 90 }, 7);
    expect(f.overGrant.unusedObjects).toEqual(['Case']);
    expect(f.overGrant.unusedVerbs).toEqual([{ object: 'Account', verbs: ['delete', 'write'] }]);
    expect(f.overGrant.scopeDowngrade).toBe('full -> api');
    expect(f.overGrant.dormant).toBe(false);
  });

  it('generates a least-privilege permission set of exactly the used object/verbs', () => {
    const f = buildFinding(app, used, granted, { since: 30, attributionRatePct: 90 }, 7);
    expect(f.recommendation.permissionSet.objectPermissions).toEqual([
      { object: 'Account', read: true, create: false, edit: false, delete: false },
    ]);
  });

  it('suppresses revoke recommendations below the soak threshold', () => {
    const f = buildFinding(app, used, granted, { since: 3, attributionRatePct: 90 }, 7);
    expect(f.notes.some((n: string) => /soak/i.test(n))).toBe(true);
    expect(f.overGrant.unusedObjects).toEqual([]); // not asserted on thin data
  });
});
