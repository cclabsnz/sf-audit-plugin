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

  // OauthOidcSettings states the username-password flow as blockOAuthUnPwFlow. It has no device
  // flow field: Device Flow is switched on per connected app.
  it('passes when the username-password flow is blocked', async () => {
    const r = await check.run(makeCtx({ blockOAuthUnPwFlow: true }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('oauth-device-and-asset-flows-ok');
    expect(r.findings[0].passed).toBe(true);
    expect(r.findings[0].detail).toContain('per connected app');
  });

  it('flags the username-password flow when it is not blocked', async () => {
    const r = await check.run(makeCtx({ blockOAuthUnPwFlow: false }));
    expect(r.findings.map((f) => f.id)).toEqual(['oauth-password-flow-enabled']);
    expect(r.findings[0].riskLevel).toBe('HIGH');
  });

  // Settings types outside jsforce's schema come back with string values.
  it.each([
    ['"false"', 'false', 'oauth-password-flow-enabled'],
    ['"true"', 'true', 'oauth-device-and-asset-flows-ok'],
  ])('reads the setting given as the string %s', async (_l, value, id) => {
    const r = await check.run(makeCtx({ blockOAuthUnPwFlow: value }));
    expect(r.findings.map((f) => f.id)).toEqual([id]);
  });

  it('never reports a device flow finding from org settings', async () => {
    const r = await check.run(makeCtx({ blockOAuthUnPwFlow: false, isDeviceFlowEnabled: true }));
    expect(r.findings.some((f) => f.id === 'oauth-device-flow-enabled')).toBe(false);
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

  it('treats a missing or unrecognised value as unknown, not blocked', async () => {
    for (const settings of [{ blockOAuthUsrAgtFlow: true }, { blockOAuthUnPwFlow: 'yes' }]) {
      const r = await check.run(makeCtx(settings));
      expect(r.findings.some((f) => f.passed)).toBe(false);
      expect(r.findings.map((f) => f.id)).toEqual(['oauth-device-and-asset-flows-advisory']);
      expect(r.findings[0].title).toContain('Username-Password Flow');
    }
  });
});
