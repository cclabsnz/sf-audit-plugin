import { jest } from '@jest/globals';
import { AuthProviderRegistrationHandlerCheck } from '../../../../src/checks/impl/AuthProviderRegistrationHandlerCheck.js';
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

describe('AuthProviderRegistrationHandlerCheck', () => {
  const check = new AuthProviderRegistrationHandlerCheck();

  it('passes when no AuthProviders have RegistrationHandlerId', async () => {
    const ctx = makeCtx({ AuthProvider: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('auth-provider-registration-handler-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags AuthProvider executing RegistrationHandler as System Administrator', async () => {
    const ctx = makeCtx({
      AuthProvider: [
        {
          Id: '0SO1',
          DeveloperName: 'Google_OIDC',
          FriendlyName: 'Google OIDC',
          ProviderType: 'OpenIdConnect',
          ExecutionUserId: '005Admin',
          RegistrationHandlerId: '01pRegHandler',
        },
      ],
      User: [
        {
          Id: '005Admin',
          Username: 'admin@corp.com',
          IsActive: true,
          Profile: { Name: 'System Administrator' },
        },
      ],
      ApexClass: [
        {
          Id: '01pRegHandler',
          Name: 'SocialRegHandler',
          Body: 'global class SocialRegHandler implements Auth.RegistrationHandler { global User createUser(Id p, Auth.UserData d) { return null; } }',
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'auth-provider-registration-handler-admin-exec');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('CRITICAL');
  });

  it('flags RegistrationHandler linking accounts by email without verification or portal scoping', async () => {
    const ctx = makeCtx({
      AuthProvider: [
        {
          Id: '0SO2',
          DeveloperName: 'Auth0_SSO',
          FriendlyName: 'Auth0 SSO',
          ProviderType: 'OpenIdConnect',
          ExecutionUserId: '005Svc',
          RegistrationHandlerId: '01pRegHandler2',
        },
      ],
      User: [
        {
          Id: '005Svc',
          Username: 'svc@corp.com',
          IsActive: true,
          Profile: { Name: 'Integration User' },
        },
      ],
      ApexClass: [
        {
          Id: '01pRegHandler2',
          Name: 'UnsafeRegHandler',
          Body: 'global class UnsafeRegHandler { public User findUser(Auth.UserData d) { return [SELECT Id FROM User WHERE Email = :d.email LIMIT 1]; } }',
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'auth-provider-registration-handler-unverified-email-linking');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('CRITICAL');
  });

  it('propagates a failure reading execution users instead of hiding admin execution', async () => {
    const ctx = makeCtx({
      'FROM AuthProvider': [
        { Id: '0SO2', DeveloperName: 'X', FriendlyName: 'X', ProviderType: 'OpenIdConnect', ExecutionUserId: '005A', RegistrationHandlerId: '01pR' },
      ],
      'FROM User': new Error('INSUFFICIENT_ACCESS: User'),
    });
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('is inconclusive, not passed, when AuthProvider is not readable', async () => {
    const ctx = makeCtx({ 'FROM AuthProvider': new Error("sObject type 'AuthProvider' is not supported.") });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['auth-provider-registration-handler-inaccessible']);
  });
});
