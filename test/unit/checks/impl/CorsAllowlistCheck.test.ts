import { jest } from '@jest/globals';
import { CorsAllowlistCheck } from '../../../../src/checks/impl/CorsAllowlistCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(records: unknown[], throws = false): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: throws
        ? (jest.fn() as any).mockRejectedValue(Object.assign(new Error('not accessible'), { errorCode: 'ENTITY_IS_INACCESSIBLE' }))
        : (jest.fn() as any).mockResolvedValue(records),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('CorsAllowlistCheck', () => {
  const check = new CorsAllowlistCheck();

  it('flags a wildcard origin as HIGH', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://*' }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'cors-wildcard-origin');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags a broad subdomain wildcard as MEDIUM', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://*.example.com' }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'cors-broad-origin');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes when only exact origins are allow-listed', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://app.example.com' }]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.passed)).toBe(true);
  });

  it('passes when no CORS entries exist', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'cors-allowlist-none' && f.passed)).toBe(true);
  });

  it('is inconclusive when the object is not accessible', async () => {
    const ctx = makeCtx([], true);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
