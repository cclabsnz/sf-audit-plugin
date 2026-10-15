import { jest } from '@jest/globals';
import { DelegatedAuthenticationExposureCheck } from '../../../../src/checks/impl/DelegatedAuthenticationExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(metaSettings: any, profiles: any[] = []): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockResolvedValue(profiles),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    metadata: {
      read: (jest.fn() as any).mockResolvedValue(metaSettings),
    } as any,
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

describe('DelegatedAuthenticationExposureCheck', () => {
  const check = new DelegatedAuthenticationExposureCheck();

  it('passes when Delegated Authentication is disabled and not assigned', async () => {
    const ctx = makeCtx({ singleSignOnSettings: { isDelegatedAuthEnabled: false } }, []);
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('delegated-authentication-exposure-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags unencrypted/insecure gateway endpoint', async () => {
    const ctx = makeCtx(
      {
        singleSignOnSettings: {
          isDelegatedAuthEnabled: true,
          delegatedGatewayUrl: 'http://auth.corp.local/services/auth',
        },
      },
      []
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'delegated-authentication-insecure-gateway');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('CRITICAL');
  });

  it('flags Delegated Authentication assigned to Administrator profiles', async () => {
    const ctx = makeCtx(
      {
        singleSignOnSettings: {
          isDelegatedAuthEnabled: true,
          delegatedGatewayUrl: 'https://auth.corp.local/services/auth',
        },
      },
      [
        {
          Id: '00eAdmin',
          Name: 'System Administrator',
          PermissionsIsSingleSignOnEnabled: true,
        },
      ]
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'delegated-authentication-admin-assigned');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('CRITICAL');
  });
});
