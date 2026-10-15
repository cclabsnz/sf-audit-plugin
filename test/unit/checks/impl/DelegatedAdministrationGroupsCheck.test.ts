import { jest } from '@jest/globals';
import { DelegatedAdministrationGroupsCheck } from '../../../../src/checks/impl/DelegatedAdministrationGroupsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(soqlResponses: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlResponses)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: '00D000000000001',
      name: 'Test Org',
      type: 'Developer Edition',
      isSandbox: false,
      instance: 'NA1',
      instanceUrl: 'https://test.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

describe('DelegatedAdministrationGroupsCheck', () => {
  const check = new DelegatedAdministrationGroupsCheck();

  it('passes when no delegated admin groups exist', async () => {
    const ctx = makeCtx({ DelegateGroup: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('delegated-administration-groups-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('marks inconclusive when query errors', async () => {
    const ctx = makeCtx({ DelegateGroup: new Error('UNEXPECTED_ERROR') });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('delegated-administration-groups-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('flags active delegated admin groups with members', async () => {
    const ctx = makeCtx({
      DelegateGroup: [{ Id: '00g1', DeveloperName: 'Helpdesk_Delegated_Admin' }],
      DelegateGroupMember: [{ Id: '0gm1', DelegateGroupId: '00g1', UserOrGroupId: '005User1' }],
      User: [{ Id: '005User1', Username: 'helpdesk@corp.com', Profile: { Name: 'Standard User' } }],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'delegated-administration-groups-active');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('propagates a failure reading group members instead of under-reporting', async () => {
    const ctx = makeCtx({
      'FROM DelegateGroupMember': new Error('INSUFFICIENT_ACCESS: DelegateGroupMember'),
      'FROM DelegateGroup': [{ Id: '00g2', DeveloperName: 'Ops' }],
    });
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('is inconclusive, not passed, when DelegateGroup is not readable', async () => {
    const ctx = makeCtx({ 'FROM DelegateGroup': new Error("sObject type 'DelegateGroup' is not supported.") });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['delegated-administration-groups-inaccessible']);
  });
});
