import { jest } from '@jest/globals';
import { ShieldTenantSecretLifecycleCheck } from '../../../../src/checks/impl/ShieldTenantSecretLifecycleCheck.js';
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

describe('ShieldTenantSecretLifecycleCheck', () => {
  const check = new ShieldTenantSecretLifecycleCheck();

  it('passes when TenantSecret is not enabled (sObject not supported)', async () => {
    const err = new Error("sObject type 'TenantSecret' is not supported.");
    const ctx = makeCtx({ TenantSecret: err });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('shield-tenant-secret-not-enabled');
    expect(r.findings[0].passed).toBe(true);
  });

  it('reports inconclusive on query error', async () => {
    const ctx = makeCtx({ TenantSecret: new Error('INSUFFICIENT_ACCESS') });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('shield-tenant-secret-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('flags active TenantSecret older than 365 days', async () => {
    const twoYearsAgo = new Date(Date.now() - 730 * 24 * 60 * 60 * 1000).toISOString();
    const ctx = makeCtx({
      TenantSecret: [
        {
          Id: '0TS1',
          Status: 'Active',
          Type: 'Data',
          Version: 1,
          CreatedDate: twoYearsAgo,
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'shield-tenant-secret-unrotated');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('MEDIUM');
  });

  it('passes when active TenantSecret was rotated recently', async () => {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const ctx = makeCtx({
      TenantSecret: [
        {
          Id: '0TS2',
          Status: 'Active',
          Type: 'Data',
          Version: 2,
          CreatedDate: thirtyDaysAgo,
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('shield-tenant-secret-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
