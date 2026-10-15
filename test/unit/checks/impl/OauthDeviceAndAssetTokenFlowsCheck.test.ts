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

  it('flags when Connected Application has Device Flow enabled', async () => {
    const ctx = makeCtx(
      null,
      [{ Id: '0CA1', Name: 'CLI App', OptionsIsDeviceFlowEnabled: true }]
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'oauth-device-flow-enabled');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });
});
