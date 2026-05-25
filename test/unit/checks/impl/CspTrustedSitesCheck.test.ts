import { jest } from '@jest/globals';
import { CspTrustedSitesCheck } from '../../../../src/checks/impl/CspTrustedSitesCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(records: unknown[]): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockResolvedValue(records),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    queries: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: {},
  };
}

describe('CspTrustedSitesCheck', () => {
  const check = new CspTrustedSitesCheck();

  it('passes when all CSP trusted sites use HTTPS', async () => {
    const ctx = makeCtx([
      { Id: '1', EndpointUrl: 'https://cdn.example.com', Context: 'ALL', IsActive: true },
      { Id: '2', EndpointUrl: 'https://fonts.googleapis.com', Context: 'ALL', IsActive: true },
    ]);
    const result = await check.run(ctx);
    expect(result.findings.some(f => f.passed)).toBe(true);
    expect(result.findings.every(f => f.riskLevel !== 'HIGH' && f.riskLevel !== 'MEDIUM')).toBe(true);
  });

  it('reports a HIGH finding for active http:// CSP trusted sites', async () => {
    const ctx = makeCtx([
      { Id: '1', EndpointUrl: 'http://insecure.example.com', Context: 'ALL', IsActive: true },
      { Id: '2', EndpointUrl: 'https://secure.example.com', Context: 'ALL', IsActive: true },
    ]);
    const result = await check.run(ctx);
    const findings = result.findings.filter(f => !f.passed);
    expect(findings).toHaveLength(1);
    expect(findings[0].riskLevel).toBe('HIGH');
    expect(findings[0].affectedItems?.[0].label).toContain('insecure.example.com');
  });

  it('groups all insecure entries into one finding with multiple affected items', async () => {
    const ctx = makeCtx([
      { Id: '1', EndpointUrl: 'http://a.com', Context: 'ALL', IsActive: true },
      { Id: '2', EndpointUrl: 'http://b.com', Context: 'CMS', IsActive: true },
    ]);
    const result = await check.run(ctx);
    const bad = result.findings.filter(f => f.riskLevel === 'HIGH');
    expect(bad).toHaveLength(1);
    expect(bad[0].affectedItems).toHaveLength(2);
  });

  it('returns a PASS finding when no CSP trusted sites exist', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some(f => f.passed)).toBe(true);
    expect(result.findings.every(f => f.riskLevel !== 'HIGH')).toBe(true);
  });
});
