import { jest } from '@jest/globals';
import { GuestUserVisibilityCheck } from '../../../../src/checks/impl/GuestUserVisibilityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  guests?: unknown[];
  guestsThrow?: boolean;
  psa?: unknown[];
  psaThrow?: boolean;
  entity?: unknown[];
  entityThrow?: boolean;
  objPerms?: unknown[];
  objPermsThrow?: boolean;
}

function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM User')) {
      if (opts.guestsThrow) throw new Error('no access');
      return opts.guests ?? [];
    }
    if (soql.includes('FROM PermissionSetAssignment')) {
      if (opts.psaThrow) throw new Error('no access');
      return opts.psa ?? [];
    }
    if (soql.includes('FROM EntityDefinition')) {
      if (opts.entityThrow) throw new Error('no access');
      return opts.entity ?? [{ QualifiedApiName: 'User', InternalSharingModel: 'Read', ExternalSharingModel: 'Private' }];
    }
    if (soql.includes('FROM ObjectPermissions')) {
      if (opts.objPermsThrow) throw new Error('no access');
      return opts.objPerms ?? [];
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

const GUEST = [{ Id: '005g', Username: 'portal site guest' }];
const psa = (over: Record<string, unknown> = {}) => ({
  AssigneeId: '005g',
  PermissionSetId: '0PS1',
  PermissionSet: { Label: 'Guest PS', PermissionsViewAllUsers: false, ...over },
});
const entity = (external: string, internal = 'Read') => [
  { QualifiedApiName: 'User', InternalSharingModel: internal, ExternalSharingModel: external },
];

describe('GuestUserVisibilityCheck', () => {
  const check = new GuestUserVisibilityCheck();

  it('passes when there are no active guest users', async () => {
    const r = await check.run(makeCtx({ guests: [] }));
    expect(r.findings.some((f) => f.id === 'guest-user-visibility-none' && f.passed)).toBe(true);
  });

  it('flags View All Users on a guest permission set as CRITICAL', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, psa: [psa({ PermissionsViewAllUsers: true })] }),
    );
    const f = r.findings.find((x) => x.id === 'guest-user-visibility-view-all-users');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('portal site guest');
    expect(f!.affectedItems?.[0].label).toContain('Guest PS');
  });

  // Secure guest record access keeps the guest OWD Private on every object, User included, so a
  // public external OWD reaches logged-in external users, not guests.
  it('flags a public external OWD on User as MEDIUM, reaching logged-in external users', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psa: [psa()], entity: entity('Read') }));
    const f = r.findings.find((x) => x.id === 'guest-user-visibility-owd');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
    expect(f!.title).toContain('logged-in external users');
    expect(f!.detail).toContain('does not reach unauthenticated guests');
    expect(f!.affectedItems?.[0].note).toContain('Read');
  });

  it('does not grade the internal OWD, which defaults to Public Read Only', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, psa: [psa()], entity: entity('Private', 'Read') }),
    );
    expect(r.findings.some((f) => f.id === 'guest-user-visibility-owd')).toBe(false);
    expect(r.findings.some((f) => f.id === 'guest-user-visibility-ok' && f.passed)).toBe(true);
  });

  it('flags a guest Read grant on the User object as HIGH', async () => {
    const r = await check.run(
      makeCtx({
        guests: GUEST,
        psa: [psa()],
        objPerms: [{ ParentId: '0PS1', SobjectType: 'User', PermissionsRead: true }],
      }),
    );
    const f = r.findings.find((x) => x.id === 'guest-user-visibility-object-read');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toContain('Guest PS');
  });

  it('reports every applicable finding at once', async () => {
    const r = await check.run(
      makeCtx({
        guests: GUEST,
        psa: [psa({ PermissionsViewAllUsers: true })],
        entity: entity('ReadWrite'),
        objPerms: [{ ParentId: '0PS1', SobjectType: 'User', PermissionsRead: true }],
      }),
    );
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain('guest-user-visibility-view-all-users');
    expect(ids).toContain('guest-user-visibility-owd');
    expect(ids).toContain('guest-user-visibility-object-read');
    expect(ids).not.toContain('guest-user-visibility-ok');
  });

  it('passes with a manual-verification note when nothing is exposed', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psa: [psa()] }));
    const f = r.findings.find((x) => x.id === 'guest-user-visibility-ok');
    expect(f).toBeDefined();
    expect(f!.passed).toBe(true);
    expect(f!.detail).toMatch(/not.*API|manual/i);
  });

  it('degrades to inconclusive when guest users cannot be queried', async () => {
    const r = await check.run(makeCtx({ guestsThrow: true }));
    expect(r.findings.some((f) => f.inconclusive)).toBe(true);
  });

  it('degrades to inconclusive when permission sets cannot be queried', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psaThrow: true }));
    expect(r.findings.some((f) => f.inconclusive)).toBe(true);
  });

  it('still grades the remaining signals when the OWD query fails', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, psa: [psa({ PermissionsViewAllUsers: true })], entityThrow: true }),
    );
    expect(r.findings.some((f) => f.id === 'guest-user-visibility-view-all-users')).toBe(true);
  });

  // The User external OWD reaches logged-in external users, so it does not wait for a guest user.
  it('reports a public User external OWD when the org has no guest user', async () => {
    const r = await check.run(makeCtx({ guests: [], entity: entity('Read') }));
    expect(r.findings.map((f) => f.id).sort()).toEqual(['guest-user-visibility-none', 'guest-user-visibility-owd']);
  });

  // Nobody is reached without an external user or a site; unreadable counts are treated as present.
  it('does not report a public User external OWD when there is no external user and no site', async () => {
    const ctx = makeCtx({ guests: [], entity: entity('Read') });
    (ctx.soql.query as any).mockResolvedValue({ records: [], totalSize: 0, done: true });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['guest-user-visibility-none']);
    const qs = (ctx.soql.query as any).mock.calls.map((c: any) => c[0] as string);
    expect(qs).toEqual(expect.arrayContaining([
      "SELECT COUNT() FROM User WHERE IsActive = true AND UserType IN ('PowerCustomerSuccess', 'CustomerSuccess', 'PowerPartner', 'CspLitePortal', 'CsnOnly', 'SelfService')",
      'SELECT COUNT() FROM Network',
    ]));
  });

  it('reports it when an external user exists, with the counts', async () => {
    const ctx = makeCtx({ guests: [], entity: entity('Read') });
    (ctx.soql.query as any).mockImplementation(async (q: string) => ({ records: [], totalSize: /FROM User/.test(q) ? 3 : 0, done: true }));
    const f = (await check.run(ctx)).findings.find((x) => x.id === 'guest-user-visibility-owd')!;
    expect(f.affectedItems![0].note).toContain('3 active external user(s), 0 Experience Cloud site(s)');
  });
});
