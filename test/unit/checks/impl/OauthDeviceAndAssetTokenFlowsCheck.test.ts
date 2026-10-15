import { jest } from '@jest/globals';
import { OauthDeviceAndAssetTokenFlowsCheck } from '../../../../src/checks/impl/OauthDeviceAndAssetTokenFlowsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(metaSettings: any, apps: any[] = []): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockResolvedValue(apps),
    } as any,
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

describe('OauthDeviceAndAssetTokenFlowsCheck', () => {
  const check = new OauthDeviceAndAssetTokenFlowsCheck();

  it('passes when both flows are disabled', async () => {
    const ctx = makeCtx({ isDeviceFlowEnabled: false, isPasswordFlowEnabled: false });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('oauth-device-and-asset-flows-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags when Device Flow is enabled in metadata', async () => {
    const ctx = makeCtx({ isDeviceFlowEnabled: true, isPasswordFlowEnabled: false });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'oauth-device-flow-enabled');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags when Username-Password Flow is enabled in metadata', async () => {
    const ctx = makeCtx({ isDeviceFlowEnabled: false, isPasswordFlowEnabled: true });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'oauth-password-flow-enabled');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('does not pass when the settings read throws', async () => {
    const ctx = makeCtx(null);
    (ctx.metadata as any).read = (jest.fn() as any).mockRejectedValue(new Error('INSUFFICIENT_ACCESS'));
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings.map((f) => f.id)).toEqual(['oauth-device-and-asset-flows-advisory']);
  });

  it('does not pass when there is no Metadata client', async () => {
    const ctx = makeCtx(null);
    (ctx as any).metadata = undefined;
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings[0].id).toBe('oauth-device-and-asset-flows-advisory');
  });

  it('treats a field missing from the settings as unknown, not disabled', async () => {
    const ctx = makeCtx({ isDeviceFlowEnabled: false });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    const f = r.findings.find((x) => x.id === 'oauth-device-and-asset-flows-advisory');
    expect(f?.title).toContain('Username-Password Flow');
    expect(f?.title).not.toContain('Device Flow and');
  });

  it('still reports an enabled flow when the other setting is unreadable', async () => {
    const ctx = makeCtx({ isPasswordFlowEnabled: true });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id).sort()).toEqual([
      'oauth-device-and-asset-flows-advisory',
      'oauth-password-flow-enabled',
    ]);
  });
});
