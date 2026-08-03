// test/unit/checks/impl/EscalationPermsCheck.test.ts
import { jest } from '@jest/globals';
import { EscalationPermsCheck } from '../../../../src/checks/impl/EscalationPermsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(records: unknown[], throws = false): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: throws
        ? (jest.fn() as any).mockRejectedValue(Object.assign(new Error('insufficient access'), { errorCode: 'INSUFFICIENT_ACCESS_RIGHTS' }))
        : (jest.fn() as any).mockResolvedValue(records),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('EscalationPermsCheck', () => {
  const check = new EscalationPermsCheck();

  it('flags users holding escalation permissions', async () => {
    const ctx = makeCtx([
      { AssigneeId: '005a', Assignee: { Username: 'u@x.com' }, PermissionSet: {
        PermissionsManageInternalUsers: true, PermissionsAssignPermissionSets: false,
        PermissionsModifyMetadata: false, PermissionsManageAuthProviders: false,
        PermissionsManageConnectedApps: false, PermissionsManageSession: false,
        PermissionsPasswordNeverExpires: false, PermissionsViewAllUsers: false } },
    ]);
    const result = await check.run(ctx);
    const finding = result.findings.find((f) => f.id === 'escalation-perms-found');
    expect(finding).toBeDefined();
    expect(finding!.riskLevel).toBe('HIGH');
    expect(finding!.affectedItems?.[0].label).toContain('u@x.com');
  });

  it('passes when no escalation permissions are granted', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'escalation-perms-ok' && f.passed)).toBe(true);
  });

  it('returns an inconclusive finding when the query is blocked', async () => {
    const ctx = makeCtx([], true);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
