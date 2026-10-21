import { jest } from '@jest/globals';
import { MyDomainLoginPolicyCheck } from '../../../../src/checks/impl/MyDomainLoginPolicyCheck.js';
import { EnhancedDomainsCheck } from '../../../../src/checks/impl/EnhancedDomainsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Organization has no MyDomain column: both checks derive My Domain from the instance URL.
// AuthConfig is a standard-API object filtered on IsActive (there is no IsDisabled column).
function makeCtx(instanceUrl: string, authConfigs: unknown[] | Error = []): { ctx: AuditContext; soqlQuery: jest.Mock; queryAll: jest.Mock } {
  const soqlQuery = (jest.fn() as any).mockImplementation((q: string) =>
    /\bMyDomain\b/.test(q)
      ? Promise.reject(new Error("No such column 'MyDomain' on entity 'Organization'"))
      : Promise.resolve({ records: [{ IsSandbox: false, InstanceName: 'NA1' }], totalSize: 1, done: true }),
  );
  const queryAll = (jest.fn() as any).mockImplementation((q: string) =>
    !/FROM AuthConfig/.test(q) || /IsDisabled/.test(q)
      ? Promise.reject(new Error('unexpected query'))
      : authConfigs instanceof Error ? Promise.reject(authConfigs) : Promise.resolve(authConfigs),
  );
  const ctx = {
    soql: { query: soqlQuery, queryAll } as any,
    tooling: { query: (jest.fn() as any).mockRejectedValue(new Error("sObject type 'AuthConfig' is not supported.")) } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'EE', isSandbox: false, instance: 'NA1', instanceUrl },
    cache: {} as any,
  } as any;
  return { ctx, soqlQuery, queryAll };
}

const ids = (r: { findings: Array<{ id: string }> }) => r.findings.map((f) => f.id);

describe('MyDomainLoginPolicyCheck', () => {
  const check = new MyDomainLoginPolicyCheck();

  it('reads My Domain from the instance URL', async () => {
    const r = await check.run(makeCtx('https://acme.my.salesforce.com').ctx);
    expect(r.findings.find((f) => f.id === 'my-domain-configured')?.title).toContain('acme');
  });

  it.each(['https://acme--uat.sandbox.my.salesforce.com', 'https://acme-dev-ed.develop.my.salesforce.com'])('recognises %s', async (url) => {
    const r = await check.run(makeCtx(url).ctx);
    expect(ids(r)).toContain('my-domain-configured');
  });

  it('reports no My Domain on a legacy instance host', async () => {
    const r = await check.run(makeCtx('https://na1.salesforce.com').ctx);
    expect(ids(r)).toEqual(['my-domain-not-configured']);
  });

  it('queries AuthConfig on the standard API, active configs only', async () => {
    const { ctx, queryAll } = makeCtx('https://acme.my.salesforce.com', [
      { DeveloperName: 'Org', AuthOptionsSaml: true, AuthOptionsUsernamePassword: true, IsActive: true },
    ]);
    const r = await check.run(ctx);
    expect(queryAll.mock.calls[0][0]).toMatch(/WHERE IsActive = true/);
    expect(ids(r)).toContain('my-domain-password-login-allowed');
  });

  it('is inconclusive, quoting the error, when AuthConfig cannot be read', async () => {
    const r = await check.run(makeCtx('https://acme.my.salesforce.com', new Error('INSUFFICIENT_ACCESS')).ctx);
    const f = r.findings.find((x) => x.id === 'my-domain-auth-config-inaccessible');
    expect(f?.inconclusive).toBe(true);
    expect(f?.detail).toContain('INSUFFICIENT_ACCESS');
  });
});

describe('EnhancedDomainsCheck', () => {
  const check = new EnhancedDomainsCheck();

  it('passes on an enhanced My Domain host', async () => {
    const r = await check.run(makeCtx('https://acme.my.salesforce.com').ctx);
    expect(r.findings.find((f) => f.id === 'enhanced-domains-enabled')?.passed).toBe(true);
  });

  it('reports no My Domain on a legacy instance host', async () => {
    const r = await check.run(makeCtx('https://na1.salesforce.com').ctx);
    expect(ids(r)).toEqual(['enhanced-domains-no-my-domain']);
  });
});
