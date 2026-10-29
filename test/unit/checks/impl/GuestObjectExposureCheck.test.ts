import { jest } from '@jest/globals';
import { GuestObjectExposureCheck } from '../../../../src/checks/impl/GuestObjectExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(
  queryAllSeq: unknown[][],
  countTotalSize = 0,
  opts: { restGet?: (path: string) => Promise<unknown>; sampleId?: string } = {},
): AuditContext {
  // The seeded rows answer the check's queries in order; the guest groups and memberships are
  // answered by text (none unless a test overrides it). Further calls, such as confirmGuestRead's
  // UserRecordAccess after the sequence, get no rows so they degrade to "unconfirmed".
  const seq = [...queryAllSeq];
  const queryAll = jest.fn(async (soql: string) => (/FROM (GroupMember|Group) WHERE/.test(soql) ? [] : (seq.shift() ?? []))) as any;
  const query = jest.fn() as any;
  query.mockImplementation(async (soql: string) => {
    if (opts.sampleId && /SELECT Id FROM /i.test(soql) && /LIMIT \d+/i.test(soql)) {
      return { totalSize: 1, done: true, records: [{ Id: opts.sampleId }] };
    }
    return { totalSize: countTotalSize, done: true, records: [] };
  });
  const rest = opts.restGet ? { get: jest.fn(opts.restGet) } : {};
  return {
    soql: { query, queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: rest as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('GuestObjectExposureCheck', () => {
  const check = new GuestObjectExposureCheck();

  it('passes when there are no guest users', async () => {
    const ctx = makeCtx([[]]);
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.id === 'guest-object-exposure-none' && f.passed)).toBe(true);
  });

  // Secure guest record access (always on since Winter '21) means a public external OWD alone gives
  // guests nothing, so without a confirmed read it is a lead, not a CRITICAL exposure.
  it.each([
    ['no record to sample', undefined, []],
    ['the guest cannot read the sampled record', 'a01x', [{ RecordId: 'a01x', HasReadAccess: false }]],
  ])('rates a public external OWD MEDIUM and unconfirmed when there is %s', async (_why, sampleId, access) => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
        access,
      ],
      0,
      { sampleId },
    );
    const r = await check.run(ctx);
    expect(r.findings.some((x) => x.id === 'guest-object-exposure-public-owd')).toBe(false);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-public-owd-unconfirmed')!;
    expect(f.riskLevel).toBe('MEDIUM');
    expect(f.affectedItems?.[0].label).toContain('Application__c');
    expect(f.detail).toContain('secure guest record access');
  });

  it('keeps a public-OWD object CRITICAL as guest-owned when the guest owns records, even unconfirmed', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
      ],
      12,
    );
    // The guest owns records; no guest sharing rule shares any.
    const ownerOnly = ctx.soql.query as any;
    const base = ownerOnly.getMockImplementation();
    ownerOnly.mockImplementation(async (soql: string) =>
      (/__Share\b/.test(soql) ? { totalSize: 0, done: true, records: [] } : base(soql)));
    const r = await check.run(ctx);
    expect(r.findings.find((x) => x.id === 'guest-object-exposure-guest-owned')!.riskLevel).toBe('CRITICAL');
    expect(r.findings.some((x) => x.id === 'guest-object-exposure-public-owd-unconfirmed')).toBe(false);
  });

  it('confirms a guest read found on any of the sampled records', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
        [{ RecordId: 'a01a', HasReadAccess: false }, { RecordId: 'a01x', HasReadAccess: true }],
      ],
      0,
      { sampleId: 'a01x' },
    );
    const r = await check.run(ctx);
    expect(r.findings.find((x) => x.id === 'guest-object-exposure-public-owd')!.riskLevel).toBe('HIGH');
    const q = (ctx.soql.queryAll as any).mock.calls.map((c: any) => c[0]).find((x: string) => /UserRecordAccess/.test(x));
    expect(q).toMatch(/RecordId IN \(/);
  });

  // Each site has its own guest user and guest sharing rules: a read by any of them confirms.
  it('confirms a read by the second site\'s guest user', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g1', ProfileId: '00e1', Username: 'g1@x' }, { Id: '005g2', ProfileId: '00e2', Username: 'g2@x' }],
        [{ AssigneeId: '005g1', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
        [{ RecordId: 'a01x', HasReadAccess: false }],
        [{ RecordId: 'a01x', HasReadAccess: true }],
      ],
      0,
      { sampleId: 'a01x' },
    );
    const r = await check.run(ctx);
    expect(r.findings.find((x) => x.id === 'guest-object-exposure-public-owd')!.riskLevel).toBe('HIGH');
  });

  it('says so when the UserRecordAccess probe fails, rather than claiming there was no record', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
      ],
      0,
      { sampleId: 'a01x' },
    );
    const answer = (ctx.soql.queryAll as any).getMockImplementation();
    (ctx.soql.queryAll as any).mockImplementation(async (soql: string) => {
      if (/FROM UserRecordAccess/.test(soql)) throw new Error('INVALID_TYPE');
      return answer(soql);
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-public-owd-unconfirmed')!;
    expect(f.affectedItems![0].note).toContain('could not be queried');
  });

  it('flags guest-owned records despite a Private OWD as CRITICAL', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Private' }],
      ],
      31906,
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-guest-owned');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('31906');
  });

  it('passes when readable objects are Private with no guest-owned records', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Account', PermissionsRead: true }],
        [{ QualifiedApiName: 'Account', ExternalSharingModel: 'Private' }],
      ],
      0,
    );
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.id === 'guest-object-exposure-ok' && f.passed)).toBe(true);
  });

  it('reports a public-OWD object HIGH when object-info models it, and surfaces UserRecordAccess confirmation', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
        [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
        [{ RecordId: 'a01x', HasReadAccess: true }], // UserRecordAccess confirms read
      ],
      0,
      { restGet: async () => ({ objectInfoName: 'Application__c' }), sampleId: 'a01x' },
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-public-owd');
    expect(f).toBeDefined();
    // HIGH like records shared under a Private OWD: the external OWD does not reach guests.
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].note).toContain('CONFIRMED');
    // Not the sharing-only tier.
    expect(r.findings.some((x) => x.id === 'guest-object-exposure-sharing-only')).toBe(false);
  });

  it('de-escalates a sharing-readable object to MEDIUM when object-info does not model it (Calendar/AuthSession tier)', async () => {
    const ctx = makeCtx(
      [
        [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
        [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
        [{ ParentId: '0PS1', SobjectType: 'Calendar', PermissionsRead: true }],
        [{ QualifiedApiName: 'Calendar', ExternalSharingModel: 'Read' }],
      ],
      0,
      {
        restGet: async () => {
          throw new Error('404 UNSUPPORTED_OBJECT');
        },
      },
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-sharing-only');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems?.[0].label).toContain('Calendar');
    // Must NOT be reported as a CRITICAL bulk-read surface.
    expect(r.findings.some((x) => x.id === 'guest-object-exposure-public-owd')).toBe(false);
  });

  // A guest user sharing rule shares records with the guest even under a Private external OWD.
  describe('guest sharing rules', () => {
    const seq = (owd: string) => [
      [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
      [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
      [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
      [{ QualifiedApiName: 'Application__c', ExternalSharingModel: owd }],
    ];
    // owned: COUNT by OwnerId; shared: COUNT on the share table (null = the query fails).
    const withCounts = (ctx: AuditContext, owned: number, shared: number | null, sampleId?: string) => {
      (ctx.soql as any).query = jest.fn(async (soql: string) => {
        if (/Share WHERE/.test(soql)) {
          if (shared === null) throw new Error('INVALID_TYPE');
          return { totalSize: shared, done: true, records: [] };
        }
        if (/OwnerId IN/.test(soql)) return { totalSize: owned, done: true, records: [] };
        if (sampleId && /LIMIT 200/.test(soql)) return { totalSize: 1, done: true, records: [{ Id: sampleId }] };
        return { totalSize: 0, done: true, records: [] };
      });
      return ctx;
    };

    // HIGH, not CRITICAL: a guest sharing rule is how a site publishes records on purpose.
    it('reports records shared with guests under a Private OWD as HIGH', async () => {
      const ctx = withCounts(makeCtx(seq('Private')), 0, 7);
      const r = await check.run(ctx);
      const f = r.findings.find((x) => x.id === 'guest-object-exposure-guest-shared')!;
      expect(f.riskLevel).toBe('HIGH');
      expect(f.affectedItems![0].label).toBe('Application__c: 7 guest share row(s)');
      expect(r.findings.some((x) => x.id === 'guest-object-exposure-ok')).toBe(false);
      const shareQuery = (ctx.soql.query as any).mock.calls.map((c: any) => c[0]).find((q: string) => /__Share/.test(q));
      expect(shareQuery).toBe(
        "SELECT COUNT() FROM Application__Share WHERE RowCause IN ('GuestRule', 'GuestParentImplicit', 'GuestPersonImplicit') OR (UserOrGroupId IN ('005g') AND RowCause != 'Owner')",
      );
    });

    // Guest user groups (whose membership GroupMember does not list), legacy group membership, and
    // groups that contain those groups, followed outwards.
    it('counts shares to a guest user group and to every public group or queue a guest is in, nested', async () => {
      const ctx = withCounts(makeCtx(seq('Private')), 0, 1);
      const answer = (ctx.soql.queryAll as any).getMockImplementation();
      const memberOf: Record<string, string[]> = { '005g': ['00GQ'], '00GQ': ['00GN'], '00GN': ['00GQ'] };
      (ctx.soql.queryAll as any).mockImplementation(async (soql: string) => {
        if (soql === "SELECT Id FROM Group WHERE Type = 'GuestUserGroup'") return [{ Id: '00GS' }];
        const m = /FROM GroupMember WHERE UserOrGroupId IN \((.*)\)$/.exec(soql);
        if (m) return [...m[1].matchAll(/'([^']+)'/g)].flatMap((x) => (memberOf[x[1]] ?? []).map((GroupId) => ({ GroupId })));
        return answer(soql);
      });
      await check.run(ctx);
      const shareQuery = (ctx.soql.query as any).mock.calls.map((c: any) => c[0]).find((q: string) => /__Share/.test(q));
      expect(shareQuery).toMatch(/ OR UserOrGroupId IN \('00GS', '00GQ', '00GN'\)$/);
      // The cycle back to 00GQ ends the walk.
      expect((ctx.soql.queryAll as any).mock.calls.filter((c: any) => /FROM GroupMember/.test(c[0]))).toHaveLength(3);
    });

    it('reads a standard object\'s share table by its own name', async () => {
      const ctx = makeCtx([
        ...seq('Private').slice(0, 2),
        [{ ParentId: '0PS1', SobjectType: 'Lead', PermissionsRead: true }],
        [{ QualifiedApiName: 'Lead', ExternalSharingModel: 'Private' }],
      ]);
      await check.run(ctx);
      const calls = (ctx.soql.query as any).mock.calls.map((c: any) => c[0] as string);
      expect(calls.some((q: string) => /FROM LeadShare WHERE/.test(q))).toBe(true);
    });

    // GuestUserAccessCheck reports these four as guest-user-sharing-exposure; counting them here
    // too would grade the same share rows twice.
    it('leaves Account, Case, Contact and Opportunity shares to the guest-access check', async () => {
      const ctx = withCounts(makeCtx([
        ...seq('Private').slice(0, 2),
        [{ ParentId: '0PS1', SobjectType: 'Account', PermissionsRead: true }],
        [{ QualifiedApiName: 'Account', ExternalSharingModel: 'Private' }],
      ]), 0, 5);
      const r = await check.run(ctx);
      expect(r.findings.some((x) => x.id === 'guest-object-exposure-guest-shared')).toBe(false);
    });

    it.each(['Read', 'Private'])('leaves guest-shared Account to the guest-access check under a %s OWD', async (owd) => {
      const ctx = withCounts(makeCtx([
        ...seq(owd).slice(0, 2),
        [{ ParentId: '0PS1', SobjectType: 'Account', PermissionsRead: true }],
        [{ QualifiedApiName: 'Account', ExternalSharingModel: owd }],
        [{ RecordId: 'a01x', HasReadAccess: true }],
      ]), 0, 5, 'a01x');
      const r = await check.run(ctx);
      expect(r.findings.filter((x) => /guest-shared|public-owd$/.test(x.id))).toEqual([]);
    });

    // A parent-controlled object's share table shows nothing, but the guest may still read records.
    it('asks UserRecordAccess when the share table shows no guest rows', async () => {
      const ctx = withCounts(makeCtx([...seq('Private'), [{ RecordId: 'a01x', HasReadAccess: true }]]), 0, 0, 'a01x');
      const r = await check.run(ctx);
      expect(r.findings.find((x) => x.id === 'guest-object-exposure-guest-shared')!.affectedItems![0].note)
        .toContain('CONFIRMED via UserRecordAccess');
    });

    it('falls back to UserRecordAccess when the share table cannot be read', async () => {
      const ctx = withCounts(makeCtx([...seq('Private'), [{ RecordId: 'a01x', HasReadAccess: true }]]), 0, null, 'a01x');
      const r = await check.run(ctx);
      const f = r.findings.find((x) => x.id === 'guest-object-exposure-guest-shared')!;
      expect(f.affectedItems![0].label).toBe('Application__c');
      expect(f.affectedItems![0].note).toContain('CONFIRMED via UserRecordAccess');
    });

    it('passes a Private object with no guest-owned or guest-shared records', async () => {
      const r = await check.run(withCounts(makeCtx(seq('Private')), 0, 0));
      expect(r.findings.map((x) => x.id)).toEqual(['guest-object-exposure-ok']);
    });

    it('prefers guest ownership when the guest owns records too', async () => {
      const r = await check.run(withCounts(makeCtx(seq('Private')), 3, 7));
      expect(r.findings.map((x) => x.id)).toEqual(['guest-object-exposure-guest-owned']);
    });

    // The external OWD does not reach guests, so share rows on a public-OWD object are graded as
    // on a Private one.
    it('grades guest share rows on a public-OWD object as shared records', async () => {
      const ctx = withCounts(makeCtx([...seq('Read'), [{ RecordId: 'a01x', HasReadAccess: false }]]), 0, 4, 'a01x');
      const r = await check.run(ctx);
      expect(r.findings.map((x) => x.id)).toEqual(['guest-object-exposure-guest-shared']);
      expect(r.findings[0].affectedItems![0].label).toBe('Application__c: 4 guest share row(s)');
    });

    it('drops a guest-shared object the UI API does not model to the sharing-only tier', async () => {
      const ctx = withCounts(makeCtx(seq('Private'), 0, { restGet: async () => { throw new Error('404'); } }), 0, 2);
      const r = await check.run(ctx);
      expect(r.findings.some((x) => x.id === 'guest-object-exposure-guest-shared')).toBe(false);
      expect(r.findings.find((x) => x.id === 'guest-object-exposure-sharing-only')!.affectedItems![0].label)
        .toBe('Application__c (records shared with guests)');
    });
  });

  // The group walk is bounded, so a deep or pathological tree cannot run away.
  it('follows nested groups at most five levels out', async () => {
    const ctx = makeCtx([
      [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
      [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
      [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
      [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Private' }],
    ]);
    const answer = (ctx.soql.queryAll as any).getMockImplementation();
    // A chain 005g -> 00G1 -> 00G2 -> ... -> 00G9.
    (ctx.soql.queryAll as any).mockImplementation(async (soql: string) => {
      const m = /FROM GroupMember WHERE UserOrGroupId IN \((.*)\)$/.exec(soql);
      if (!m) return answer(soql);
      return [...m[1].matchAll(/'([^']+)'/g)].flatMap((x) => {
        const n = x[1] === '005g' ? 0 : Number(x[1].slice(3));
        return n < 9 ? [{ GroupId: `00G${n + 1}` }] : [];
      });
    });
    await check.run(ctx);
    expect((ctx.soql.queryAll as any).mock.calls.filter((c: any) => /FROM GroupMember/.test(c[0]))).toHaveLength(5);
    const shareQuery = (ctx.soql.query as any).mock.calls.map((c: any) => c[0]).find((q: string) => /__Share/.test(q));
    expect(shareQuery).toMatch(/UserOrGroupId IN \('00G1', '00G2', '00G3', '00G4', '00G5'\)$/);
  });
});
