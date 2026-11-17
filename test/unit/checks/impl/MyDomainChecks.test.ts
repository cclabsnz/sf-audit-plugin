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
    // Experience Cloud site and portal login pages are separate AuthConfig rows.
    expect(queryAll.mock.calls[0][0]).toMatch(/AND Type = 'Org'/);
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
  const withSettings = (settings: unknown, url = 'https://acme.my.salesforce.com') => {
    const { ctx } = makeCtx(url);
    (ctx as any).metadata = {
      read: (jest.fn() as any).mockImplementation((type: string, name: string) =>
        type === 'MyDomainSettings' && name === 'MyDomain'
          ? settings instanceof Error ? Promise.reject(settings) : Promise.resolve(settings)
          : Promise.resolve(null),
      ),
    };
    return ctx;
  };

  it('passes when MyDomainSettings reports the enhanced suffix', async () => {
    const r = await check.run(withSettings({ myDomainSuffix: 'MySalesforce', domainPartition: 'none' }));
    expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-enabled']);
    expect(r.findings[0].passed).toBe(true);
  });

  it('passes a partitioned sandbox domain, which requires enhanced domains', async () => {
    const r = await check.run(withSettings({ domainPartition: 'sandbox' }, 'https://acme--uat.sandbox.my.salesforce.com'));
    expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-enabled']);
  });

  it('fails when MyDomainSettings reports my.salesforce.com without enhanced domains', async () => {
    const r = await check.run(withSettings({ myDomainSuffix: 'MySalesforceLimited', domainPartition: 'none' }));
    expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-not-detected']);
    expect(r.findings[0].riskLevel).toBe('MEDIUM');
  });

  it('does not pass on the instance URL alone, which is the same with or without enhanced domains', async () => {
    const r = await check.run(makeCtx('https://acme.my.salesforce.com').ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-unverified']);
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeFalsy();
  });

  it('is inconclusive, quoting the error, when MyDomainSettings cannot be read', async () => {
    const r = await check.run(withSettings(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings[0].id).toBe('enhanced-domains-unverified');
    expect(r.findings[0].detail).toContain('INSUFFICIENT_ACCESS');
  });

  it('is inconclusive on an unmapped suffix', async () => {
    const r = await check.run(withSettings({ myDomainSuffix: 'Restricted1', domainPartition: 'none' }));
    expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-unverified']);
  });

  it('does not fail government or China hosts on their host name', async () => {
    for (const url of ['https://acme.my.salesforce.mil', 'https://acme.my.sfcrmproducts.cn']) {
      const r = await check.run(withSettings({ myDomainSuffix: 'MySalesforce' }, url));
      expect(r.findings.map((f) => f.id)).toEqual(['enhanced-domains-enabled']);
    }
  });

  it('reports no My Domain on a legacy instance host', async () => {
    const r = await check.run(makeCtx('https://na1.salesforce.com').ctx);
    expect(ids(r)).toEqual(['enhanced-domains-no-my-domain']);
  });
});
