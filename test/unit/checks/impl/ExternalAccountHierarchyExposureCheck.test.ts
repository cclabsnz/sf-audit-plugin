import { jest } from '@jest/globals';
import { ExternalAccountHierarchyExposureCheck } from '../../../../src/checks/impl/ExternalAccountHierarchyExposureCheck.js';
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

describe('ExternalAccountHierarchyExposureCheck', () => {
  const check = new ExternalAccountHierarchyExposureCheck();

  it('passes when no super users or external hierarchies exist', async () => {
    const ctx = makeCtx({ User: [], ExternalAccountHierarchy: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('external-account-hierarchy-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags portal users with IsPrmSuperUser enabled', async () => {
    const ctx = makeCtx({
      User: [
        {
          Id: '005xx0000000001',
          Username: 'superuser@partner.com',
          IsActive: true,
          IsPrmSuperUser: true,
        },
      ],
      ExternalAccountHierarchy: [],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'external-account-hierarchy-super-users');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags active ExternalAccountHierarchy configurations', async () => {
    const ctx = makeCtx({
      User: [],
      ExternalAccountHierarchy: [
        {
          Id: '0EA1',
          MasterLabel: 'Global Dealer Hierarchy',
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'external-account-hierarchy-active');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });
});
