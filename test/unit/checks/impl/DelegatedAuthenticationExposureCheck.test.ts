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

  it('gives an advisory, not a pass, when there is no Metadata client', async () => {
    const ctx = makeCtx(null, []);
    (ctx as any).metadata = undefined;
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings.map((f) => f.id)).toEqual(['delegated-authentication-advisory']);
  });

  it('gives an advisory, not silence, when the settings read fails and admins hold SSO', async () => {
    const ctx = makeCtx(null, [{ Id: '00eA', Name: 'System Administrator', PermissionsIsSingleSignOnEnabled: true }]);
    (ctx.metadata as any).read = (jest.fn() as any).mockRejectedValue(new Error('INSUFFICIENT_ACCESS'));
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['delegated-authentication-advisory']);
    expect(r.findings[0].detail).toContain('1 administrator profile');
  });

  it('passes, rather than emitting nothing, when enabled over HTTPS with no admin profiles', async () => {
    const ctx = makeCtx(
      { singleSignOnSettings: { isDelegatedAuthEnabled: true, delegatedGatewayUrl: 'https://sso.example.com/auth' } },
      [{ Id: '00eB', Name: 'Standard User', PermissionsIsSingleSignOnEnabled: true }],
    );
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['delegated-authentication-exposure-ok']);
  });

  it('propagates a permission error on Profile instead of passing', async () => {
    const ctx = makeCtx({ singleSignOnSettings: { isDelegatedAuthEnabled: false } });
    (ctx.soql as any).queryAll = (jest.fn() as any).mockRejectedValue(new Error('INSUFFICIENT_ACCESS'));
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });
});
