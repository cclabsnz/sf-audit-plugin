import { jest } from '@jest/globals';
import { GuestObjectExposureCheck } from '../../../../src/checks/impl/GuestObjectExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(
  queryAllSeq: unknown[][],
  countTotalSize = 0,
  opts: { restGet?: (path: string) => Promise<unknown>; sampleId?: string } = {},
): AuditContext {
  const queryAll = jest.fn() as any;
  for (const r of queryAllSeq) queryAll.mockResolvedValueOnce(r);
  // queryAll is also used by confirmGuestRead (UserRecordAccess) after the seeded
  // sequence; default any further calls to empty so it degrades to "unconfirmed".
  queryAll.mockResolvedValue([]);
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
    expect(r.findings.find((x) => x.id === 'guest-object-exposure-public-owd')!.riskLevel).toBe('CRITICAL');
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
    expect(r.findings.find((x) => x.id === 'guest-object-exposure-public-owd')!.riskLevel).toBe('CRITICAL');
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
    (ctx.soql.queryAll as any).mockRejectedValueOnce(new Error('INVALID_TYPE'));
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

  it('keeps a public-OWD object CRITICAL when object-info models it, and surfaces UserRecordAccess confirmation', async () => {
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
    expect(f!.riskLevel).toBe('CRITICAL');
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
});
