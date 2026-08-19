import { jest } from '@jest/globals';
import type { AuditContext, AuditOptions } from '@cclabsnz/sf-core';
import type { CspTrustedSite } from '@cclabsnz/sf-core';

// Mock node:dns/promises before importing the check (ESM module mock). `resolve` is the
// only DNS entry point the check uses (resolve(domain, 'NS')). No real network.
const resolveMock = jest.fn<(name: string, rrtype: string) => Promise<string[]>>();
jest.unstable_mockModule('node:dns/promises', () => ({
  resolve: resolveMock,
}));

const { TrustedUrlHygieneCheck } = await import(
  '../../../../src/checks/impl/TrustedUrlHygieneCheck.js'
);

function makeCtx(
  cspTrustedSites: CspTrustedSite[] | undefined,
  options?: AuditOptions,
): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    options,
    cache: { cspTrustedSites },
  } as any;
}

function site(endpointUrl: string, over: Partial<CspTrustedSite> = {}): CspTrustedSite {
  return { developerName: 'X', endpointUrl, isActive: true, context: 'ALL', ...over };
}

function dnsError(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

describe('TrustedUrlHygieneCheck', () => {
  const check = new TrustedUrlHygieneCheck();

  beforeEach(() => resolveMock.mockReset());

  it('declares its cache contract', () => {
    expect(check.id).toBe('trusted-url-hygiene');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(['cspTrustedSites']);
  });

  it('returns no findings when the cache key is absent', async () => {
    const result = await check.run(makeCtx(undefined));
    expect(result.findings).toHaveLength(0);
    expect(resolveMock).not.toHaveBeenCalled();
  });

  it('default mode: flags a non-Salesforce domain as LOW', async () => {
    const result = await check.run(makeCtx([site('https://analytics.acme.com')]));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].riskLevel).toBe('LOW');
    expect(result.findings[0].id).toBe('trusted-url-hygiene-review-analytics.acme.com');
    expect(result.findings[0].detail).toMatch(/ForcedLeak/);
    expect(resolveMock).not.toHaveBeenCalled();
  });

  it('default mode: stays silent for Salesforce-family domains', async () => {
    const result = await check.run(
      makeCtx([
        site('https://my.force.com'),
        site('https://cdn.sfdcstatic.com'),
        site('https://example.my.salesforce.com'),
        site('https://foo.salesforceliveagent.com'),
      ]),
    );
    expect(result.findings).toHaveLength(0);
  });

  it('default mode: ignores inactive trusted sites', async () => {
    const result = await check.run(
      makeCtx([site('https://analytics.acme.com', { isActive: false })]),
    );
    expect(result.findings).toHaveLength(0);
  });

  it('resolve mode: NXDOMAIN/ENOTFOUND yields a CRITICAL unresolvable finding', async () => {
    resolveMock.mockRejectedValue(dnsError('ENOTFOUND'));
    const result = await check.run(
      makeCtx([site('https://gone.acme.com')], { resolveDomains: true }),
    );
    expect(resolveMock).toHaveBeenCalledWith('gone.acme.com', 'NS');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].riskLevel).toBe('CRITICAL');
    expect(result.findings[0].id).toBe('trusted-url-hygiene-unresolvable-gone.acme.com');
  });

  it('resolve mode: parking nameservers yield a CRITICAL parked finding', async () => {
    resolveMock.mockResolvedValue(['ns1.sedoparking.com', 'ns2.sedoparking.com']);
    const result = await check.run(
      makeCtx([site('https://lapsed.acme.com')], { resolveDomains: true }),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].riskLevel).toBe('CRITICAL');
    expect(result.findings[0].id).toBe('trusted-url-hygiene-parked-lapsed.acme.com');
    expect(result.findings[0].detail).toMatch(/sedoparking/);
  });

  it('resolve mode: a timeout degrades to an INFO could-not-verify finding, never throws', async () => {
    resolveMock.mockImplementation(
      () => new Promise((_, reject) => { setTimeout(() => reject(dnsError('ETIMEDOUT')), 1); }),
    );
    const result = await check.run(
      makeCtx([site('https://slow.acme.com')], { resolveDomains: true }),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].riskLevel).toBe('INFO');
    expect(result.findings[0].id).toBe('trusted-url-hygiene-unverified-slow.acme.com');
  });

  it('resolve mode: a healthy non-parking domain keeps the LOW review finding', async () => {
    resolveMock.mockResolvedValue(['ns1.awsdns.com', 'ns2.awsdns.com']);
    const result = await check.run(
      makeCtx([site('https://analytics.acme.com')], { resolveDomains: true }),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].riskLevel).toBe('LOW');
    expect(result.findings[0].id).toBe('trusted-url-hygiene-review-analytics.acme.com');
  });

  it('resolve mode: does not DNS-check Salesforce-family domains', async () => {
    resolveMock.mockResolvedValue(['ns1.sedoparking.com']);
    const result = await check.run(
      makeCtx([site('https://cdn.sfdcstatic.com')], { resolveDomains: true }),
    );
    expect(result.findings).toHaveLength(0);
    expect(resolveMock).not.toHaveBeenCalled();
  });

  it('resolve mode: mixes outcomes across several domains', async () => {
    resolveMock.mockImplementation(async (name: string) => {
      if (name === 'gone.acme.com') throw dnsError('ENOTFOUND');
      if (name === 'parked.acme.com') return ['ns1.bodis.com'];
      return ['ns1.cloudflare.com'];
    });
    const result = await check.run(
      makeCtx(
        [site('https://gone.acme.com'), site('https://parked.acme.com'), site('https://ok.acme.com')],
        { resolveDomains: true },
      ),
    );
    const byId = Object.fromEntries(result.findings.map((f) => [f.id, f.riskLevel]));
    expect(byId['trusted-url-hygiene-unresolvable-gone.acme.com']).toBe('CRITICAL');
    expect(byId['trusted-url-hygiene-parked-parked.acme.com']).toBe('CRITICAL');
    expect(byId['trusted-url-hygiene-review-ok.acme.com']).toBe('LOW');
  });
});
