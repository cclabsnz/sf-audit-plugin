import { jest } from '@jest/globals';
import { AuthProvidersCheck } from '../../../../src/checks/impl/AuthProvidersCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(opts: { providers?: unknown[]; providersThrow?: boolean; saml?: unknown[] }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('AuthProvider')) {
      if (opts.providersThrow) throw new Error('no access');
      return opts.providers ?? [];
    }
    if (soql.includes('SamlSsoConfig')) return opts.saml ?? [];
    return [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('AuthProvidersCheck', () => {
  const check = new AuthProvidersCheck();

  it('is inconclusive when AuthProvider is inaccessible', async () => {
    const r = await check.run(makeCtx({ providersThrow: true }));
    expect(r.findings[0].id).toBe('auth-providers-inconclusive');
  });

  it('flags social providers as MEDIUM', async () => {
    const r = await check.run(makeCtx({ providers: [{ Id: '1', DeveloperName: 'g', ProviderType: 'Google', FriendlyName: 'Google' }] }));
    expect(r.findings.find((f) => f.id === 'auth-providers-social')?.riskLevel).toBe('MEDIUM');
  });

  it('inventories SAML configs and non-social providers', async () => {
    const r = await check.run(makeCtx({ providers: [], saml: [{ Id: '2', DeveloperName: 'CorpIdP', Issuer: 'https://idp' }] }));
    expect(r.findings.some((f) => f.id === 'auth-providers-inventory')).toBe(true);
  });

  it('passes when no external identity is configured', async () => {
    const r = await check.run(makeCtx({ providers: [], saml: [] }));
    expect(r.findings.some((f) => f.id === 'auth-providers-none' && f.passed)).toBe(true);
  });
});
