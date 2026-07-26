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
    if (opts.sampleId && /SELECT Id FROM /i.test(soql) && /LIMIT 1/i.test(soql)) {
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

  it('flags an object with public external OWD as CRITICAL', async () => {
    const ctx = makeCtx([
      [{ Id: '005g', ProfileId: '00e', Username: 'guest@x' }],
      [{ AssigneeId: '005g', PermissionSetId: '0PS1' }],
      [{ ParentId: '0PS1', SobjectType: 'Application__c', PermissionsRead: true }],
      [{ QualifiedApiName: 'Application__c', ExternalSharingModel: 'Read' }],
    ]);
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'guest-object-exposure-public-owd');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('Application__c');
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
