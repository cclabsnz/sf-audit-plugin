import { jest } from '@jest/globals';
import { GuestUserAccessCheck } from '../../../../src/checks/impl/GuestUserAccessCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type QueryAll = (soql: string) => Promise<unknown[]>;
type Query = (soql: string) => Promise<{ records: unknown[] }>;

function makeCtx(opts: {
  queryAll?: QueryAll;
  query?: Query;
  healthCloudInstalled?: boolean;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((s: string) =>
        opts.queryAll ? opts.queryAll(s) : Promise.resolve([]),
      ),
      query: (jest.fn() as any).mockImplementation((s: string) =>
        opts.query ? opts.query(s) : Promise.resolve({ records: [] }),
      ),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { healthCloudInstalled: opts.healthCloudInstalled } as any,
  } as any;
}

const guest = (id = '005G', profileId = '00eG', username = 'guest@site.com') => ({
  Id: id, ProfileId: profileId, Username: username,
});

const perm = (over: Record<string, unknown> = {}) => ({
  ParentId: '00eG', SobjectType: 'Account',
  PermissionsCreate: false, PermissionsEdit: false,
  PermissionsDelete: false, PermissionsRead: false,
  ...over,
});

/** Route a query by the object it hits, so fixtures do not depend on call order. */
const router = (opts: { users?: unknown[]; perms?: unknown[] }): QueryAll => (soql) => {
  if (/FROM User\b/i.test(soql)) return Promise.resolve(opts.users ?? []);
  if (/FROM ObjectPermissions/i.test(soql)) return Promise.resolve(opts.perms ?? []);
  return Promise.resolve([]);
};

describe('GuestUserAccessCheck', () => {
  const check = new GuestUserAccessCheck();

  it('declares its identity and cache contract', () => {
    expect(check.id).toBe('guest-user-access');
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['healthCloudInstalled']));
  });

  it('passes when there are no active guest users', async () => {
    const r = await check.run(makeCtx({ queryAll: router({ users: [] }) }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('guest-user-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('only queries for ACTIVE guest users', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({
      queryAll: (s) => { seen.push(s); return Promise.resolve([]); },
    }));
    const userQuery = seen.find((s) => /FROM User\b/i.test(s));
    expect(userQuery).toMatch(/UserType\s*=\s*'Guest'/i);
    expect(userQuery).toMatch(/IsActive\s*=\s*true/i);
  });

  // The CRITICAL path: an unauthenticated identity that can change data.
  it.each([
    ['PermissionsCreate', { PermissionsCreate: true }],
    ['PermissionsEdit', { PermissionsEdit: true }],
    ['PermissionsDelete', { PermissionsDelete: true }],
  ])('flags %s on a guest profile as CRITICAL write access', async (_label, over) => {
    const r = await check.run(makeCtx({
      queryAll: router({ users: [guest()], perms: [perm(over)] }),
    }));
    const f = r.findings.find((x) => x.id === 'guest-user-write-access');
    // RULE-101: writing is tampering, not the check's disclosure.
    expect(f?.threats).toEqual({ stride: ['T', 'I'] });
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('Account');
  });

  it('flags read-only guest access as HIGH, per SBS-CPORTAL-002', async () => {
    const r = await check.run(makeCtx({
      queryAll: router({ users: [guest()], perms: [perm({ PermissionsRead: true })] }),
    }));
    const f = r.findings.find((x) => x.id === 'guest-user-read-access');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    // Read access alone must not be reported as write access.
    expect(r.findings.some((x) => x.id === 'guest-user-write-access')).toBe(false);
  });

  it('reports write access rather than read when a profile has both', async () => {
    const r = await check.run(makeCtx({
      queryAll: router({
        users: [guest()],
        perms: [perm({ PermissionsRead: true, PermissionsEdit: true })],
      }),
    }));
    expect(r.findings.some((x) => x.id === 'guest-user-write-access')).toBe(true);
    expect(r.findings.some((x) => x.id === 'guest-user-read-access')).toBe(false);
  });

  it('attributes a profile permission to every guest user on that profile', async () => {
    const r = await check.run(makeCtx({
      queryAll: router({
        users: [guest('005A', '00eG', 'a@x.com'), guest('005B', '00eG', 'b@x.com')],
        perms: [perm({ PermissionsEdit: true })],
      }),
    }));
    const f = r.findings.find((x) => x.id === 'guest-user-write-access')!;
    expect(f.affectedItems).toHaveLength(2);
    expect(JSON.stringify(f.affectedItems)).toContain('a@x.com');
    expect(JSON.stringify(f.affectedItems)).toContain('b@x.com');
  });

  it('flags share rows that give a guest user access', async () => {
    const r = await check.run(makeCtx({
      queryAll: router({ users: [guest()] }),
      query: (s) => Promise.resolve(
        (/FROM AccountShare/i.test(s) ? { records: [], totalSize: 3 } : { records: [], totalSize: 0 }) as any,
      ),
    }));
    const f = r.findings.find((x) => x.id === 'guest-user-sharing-exposure');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.title).toContain('3');
  });

  // 'SharingRule' is not a RowCause value; it matched nothing and hid every guest sharing rule.
  // Guest rule rows count whoever they name; legacy manual, Apex and group shares count when they
  // name a guest user or a group it belongs to.
  it('counts guest rule rows and legacy shares naming a guest or its groups', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({
      queryAll: (s) => (/FROM GroupMember/.test(s) ? Promise.resolve([{ GroupId: '00GQ' }]) : router({ users: [guest()] })(s)),
      query: (s) => { seen.push(s); return Promise.resolve({ records: [], totalSize: 0 } as any); },
    }));
    const shares = seen.filter((s) => /FROM \w+Share /.test(s));
    expect(shares.map((s) => /FROM (\w+)/.exec(s)![1])).toEqual(['AccountShare', 'CaseShare', 'ContactShare', 'OpportunityShare']);
    for (const s of shares) {
      expect(s).toContain("RowCause IN ('GuestRule', 'GuestParentImplicit', 'GuestPersonImplicit')");
      expect(s).toContain("(UserOrGroupId IN ('005G') AND RowCause != 'Owner')");
      expect(s).toContain("UserOrGroupId IN ('00GQ')");
      expect(s).not.toMatch(/'SharingRule'/);
    }
  });

  it('falls back to the baseline finding when guests exist but hold no access', async () => {
    const r = await check.run(makeCtx({ queryAll: router({ users: [guest()] }) }));
    const f = r.findings.find((x) => x.id === 'guest-user-baseline');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
    // The baseline is mutually exclusive with the three exposure findings.
    expect(r.findings).toHaveLength(1);
  });

  it('includes Health Cloud objects only when the cache says it is installed', async () => {
    const withHc: string[] = [];
    await check.run(makeCtx({
      healthCloudInstalled: true,
      queryAll: (s) => { withHc.push(s); return Promise.resolve(/FROM User\b/i.test(s) ? [guest()] : []); },
    }));
    const withoutHc: string[] = [];
    await check.run(makeCtx({
      healthCloudInstalled: false,
      queryAll: (s) => { withoutHc.push(s); return Promise.resolve(/FROM User\b/i.test(s) ? [guest()] : []); },
    }));
    const hcQuery = withHc.find((s) => /FROM ObjectPermissions/i.test(s))!;
    const plainQuery = withoutHc.find((s) => /FROM ObjectPermissions/i.test(s))!;
    expect(hcQuery).toContain('CarePlan__c');
    expect(plainQuery).not.toContain('CarePlan__c');
    // Standard objects are always in scope.
    expect(plainQuery).toContain('Account');
  });

  it('degrades to the baseline when ObjectPermissions is not readable', async () => {
    const r = await check.run(makeCtx({
      queryAll: (s) => {
        if (/FROM User\b/i.test(s)) return Promise.resolve([guest()]);
        if (/FROM ObjectPermissions/i.test(s)) return Promise.reject(new Error('INSUFFICIENT_ACCESS'));
        return Promise.resolve([]);
      },
    }));
    // A permission query it cannot run must not be reported as "no exposure found" silently
    // failing — it still reports the guest users themselves.
    expect(r.findings.some((x) => x.id === 'guest-user-baseline')).toBe(true);
  });

  it('survives a share table that is not queryable', async () => {
    const r = await check.run(makeCtx({
      queryAll: router({ users: [guest()] }),
      query: () => Promise.reject(new Error('no such object')),
    }));
    expect(r.findings.some((x) => x.id === 'guest-user-baseline')).toBe(true);
  });

  // A share the table does not show (Contact controlled by its parent) still lets the guest read.
  it('asks UserRecordAccess when the share table shows no guest rows', async () => {
    const r = await check.run(makeCtx({
      queryAll: (s) => (/FROM UserRecordAccess WHERE UserId = '005G'/.test(s) && /'003x'/.test(s)
        ? Promise.resolve([{ RecordId: '003x', HasReadAccess: true }])
        : router({ users: [guest()] })(s)),
      query: (s) => Promise.resolve((/SELECT Id FROM Contact LIMIT 200/.test(s)
        ? { records: [{ Id: '003x' }], totalSize: 1 }
        : { records: [], totalSize: 0 }) as any),
    }));
    const f = r.findings.find((x) => x.id === 'guest-user-sharing-exposure')!;
    expect(f.title).toBe('Guest users can read Account, Case, Contact or Opportunity records on 1 object(s)');
    expect(f.affectedItems).toEqual([expect.objectContaining({ label: 'ContactShare', note: expect.stringContaining('UserRecordAccess confirms') })]);
  });
});
