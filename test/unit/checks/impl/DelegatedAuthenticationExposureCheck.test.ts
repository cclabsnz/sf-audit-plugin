import { jest } from '@jest/globals';
import { DelegatedAuthenticationExposureCheck } from '../../../../src/checks/impl/DelegatedAuthenticationExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(profiles: any[] = [], ssoFieldPresent = true): AuditContext {
  const profileFields = ['Id', 'Name', ...(ssoFieldPresent ? ['PermissionsIsSsoEnabled'] : [])];
  return {
    soql: {
      queryAll: (jest.fn() as any).mockResolvedValue(profiles),
    } as any,
    tooling: {} as any,
    rest: {
      get: (jest.fn() as any).mockResolvedValue({ fields: profileFields.map((name) => ({ name })) }),
    } as any,
    metadata: {
      read: (jest.fn() as any).mockResolvedValue(null),
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

  it('passes, without querying Profile, when the org has no delegated-auth permission field', async () => {
    const ctx = makeCtx([], false);
    const r = await check.run(ctx);
    expect((ctx.soql.queryAll as any).mock.calls).toHaveLength(0);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ id: 'delegated-authentication-exposure-ok', passed: true });
  });

  it('flags Delegated Authentication assigned to Administrator profiles', async () => {
    const ctx = makeCtx([{ Id: '00eAdmin', Name: 'System Administrator', PermissionsIsSsoEnabled: true }]);
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'delegated-authentication-admin-assigned');
    expect(f?.riskLevel).toBe('CRITICAL');
  });

  // The gateway URL is not in any documented API, so the check never claims to have read it.
  it('asks for the gateway to be verified by hand, and never passes, when the permission exists', async () => {
    const ctx = makeCtx([{ Id: '00eB', Name: 'Standard User', PermissionsIsSsoEnabled: true }]);
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['delegated-authentication-advisory']);
    expect(r.findings[0].riskLevel).toBe('INFO');
    expect(r.findings[0].detail).toMatch(/cannot check/);
    expect(r.findings.some((f) => f.passed)).toBe(false);
  });

  it('does not read SecuritySettings, which documents no delegated-auth flag or gateway URL', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    expect((ctx.metadata!.read as any).mock.calls).toHaveLength(0);
  });

  it('propagates a permission error on Profile instead of passing', async () => {
    const ctx = makeCtx();
    (ctx.soql as any).queryAll = (jest.fn() as any).mockRejectedValue(new Error('INSUFFICIENT_ACCESS'));
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('queries the real permission field name, PermissionsIsSsoEnabled', async () => {
    const ctx = makeCtx();
    await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[0][0] as string;
    expect(q).toContain('PermissionsIsSsoEnabled = true');
    expect(q).not.toContain('PermissionsIsSingleSignOnEnabled');
  });
});
