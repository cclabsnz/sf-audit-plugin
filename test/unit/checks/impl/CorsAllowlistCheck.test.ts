import { jest } from '@jest/globals';
import { CorsAllowlistCheck } from '../../../../src/checks/impl/CorsAllowlistCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import { CHECK_META } from '../../../../src/findings/CheckMeta.js';

function makeCtx(records: unknown[], throws = false): AuditContext {
  return {
    // CorsWhitelistEntry is a standard-API object; the Tooling API rejects it.
    soql: {
      queryAll: throws
        ? (jest.fn() as any).mockRejectedValue(Object.assign(new Error('not accessible'), { errorCode: 'ENTITY_IS_INACCESSIBLE' }))
        : (jest.fn() as any).mockResolvedValue(records),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockRejectedValue(Object.assign(new Error("sObject type 'CorsWhitelistEntry' is not supported."), { errorCode: 'INVALID_TYPE' })),
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

  // An allowlist entry exposes no stored credential: script on an allowed origin needs a token or
  // session of its own. The wording must not promise theft, and must state that precondition.
  it('never claims token or credential theft, and says a token is needed', async () => {
    const overstated = /token theft|steal|credential theft|session-scoped|authenticated cross-origin/i;
    const all = [
      ...(await check.run(makeCtx([{ Id: '1', UrlPattern: 'https://*' }, { Id: '2', UrlPattern: 'https://*.example.com' }]))).findings,
      ...(await check.run(makeCtx([]))).findings,
    ];
    for (const f of all) expect(`${f.id}: ${f.title} ${f.detail}`).not.toMatch(overstated);
    expect(check.description).not.toMatch(overstated);
    expect(CHECK_META['cors-allowlist'].impact).not.toMatch(overstated);
    expect(CHECK_META['cors-allowlist'].impact).toMatch(/token or session/);
    expect(all.find((f) => f.id === 'cors-wildcard-origin')!.detail).toMatch(/session ID or OAuth access token/);
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
