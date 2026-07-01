import { jest } from '@jest/globals';
import { GuestObjectExposureCheck } from '../../../../src/checks/impl/GuestObjectExposureCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(queryAllSeq: unknown[][], countTotalSize = 0): AuditContext {
  const queryAll = jest.fn() as any;
  for (const r of queryAllSeq) queryAll.mockResolvedValueOnce(r);
  const query = jest.fn() as any;
  query.mockResolvedValue({ totalSize: countTotalSize, done: true, records: [] });
  return {
    soql: { query, queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
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
});
