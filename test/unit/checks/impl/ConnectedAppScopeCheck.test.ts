import { jest } from '@jest/globals';
import { ConnectedAppScopeCheck } from '../../../../src/checks/impl/ConnectedAppScopeCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(apps: unknown[] | Error): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        apps instanceof Error ? Promise.reject(apps) : Promise.resolve(apps),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const app = (
  Name: string,
  opts: { scopes?: string[]; validity?: number; policy?: string } = {},
) => ({
  Id: `0CiA${Name}`,
  Name,
  Metadata: {
    oauthConfig: {
      scopes: opts.scopes ?? [],
      ...(opts.validity !== undefined ? { refreshTokenValidityPeriod: opts.validity } : {}),
    },
    ...(opts.policy ? { oauthPolicy: { refreshTokenPolicy: opts.policy } } : {}),
  },
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ConnectedAppScopeCheck', () => {
  const check = new ConnectedAppScopeCheck();

  it('is inconclusive when connected app metadata cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('connected-app-scope-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('passes when the org has no connected apps', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('connected-app-scope-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('passes when apps use scoped permissions and bounded tokens', async () => {
    const r = await check.run(makeCtx([app('Good', { scopes: ['Api', 'Web'], validity: 90 })]));
    expect(r.findings[0].id).toBe('connected-app-scope-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it.each(['Full', 'full'])('flags the %s scope as HIGH', async (scope) => {
    const r = await check.run(makeCtx([app('Broad', { scopes: [scope], validity: 90 })]));
    const f = find(r, 'connected-app-full-scope')!;
    expect(f.riskLevel).toBe('HIGH');
    expect(f.affectedItems?.[0].note).toContain(scope);
  });

  it('does not flag narrower scopes', async () => {
    const r = await check.run(makeCtx([
      app('A', { scopes: ['Api', 'Web', 'OpenID', 'CustomPermissions'], validity: 30 }),
    ]));
    expect(find(r, 'connected-app-full-scope')).toBeUndefined();
  });

  // Two encodings of "never expires", both of which must be caught.
  it.each([
    ['validityPeriod -1', { scopes: ['Api'], validity: -1 }],
    ['policy infinite', { scopes: ['Api'], policy: 'infinite' }],
  ])('flags an infinite refresh token via %s', async (_label, opts) => {
    const r = await check.run(makeCtx([app('Forever', opts)]));
    const f = find(r, 'connected-app-infinite-refresh-token')!;
    expect(f.riskLevel).toBe('MEDIUM');
  });

  // An app with no scopes issues no tokens, so an unbounded policy on it is not a risk.
  it('ignores an infinite token policy on an app with no OAuth scopes', async () => {
    const r = await check.run(makeCtx([app('NonOauth', { scopes: [], validity: -1 })]));
    expect(find(r, 'connected-app-infinite-refresh-token')).toBeUndefined();
    expect(r.findings[0].id).toBe('connected-app-scope-ok');
  });

  it('treats a bounded validity period as acceptable', async () => {
    const r = await check.run(makeCtx([app('Bounded', { scopes: ['Api'], validity: 90 })]));
    expect(find(r, 'connected-app-infinite-refresh-token')).toBeUndefined();
  });

  // Full scope plus a token that never expires is a permanent admin-equivalent credential,
  // so it escalates rather than being reported as two separate mid-level findings.
  it('escalates Full scope combined with an infinite token to CRITICAL', async () => {
    const r = await check.run(makeCtx([app('Worst', { scopes: ['Full'], validity: -1 })]));
    const f = find(r, 'connected-app-full-scope-infinite-token')!;
    expect(f.riskLevel).toBe('CRITICAL');
    expect(f.affectedItems?.[0].label).toBe('Worst');
  });

  it('does not double-count a compound app in the infinite-token finding', async () => {
    const r = await check.run(makeCtx([app('Worst', { scopes: ['Full'], validity: -1 })]));
    // It appears in the Full-scope finding and the compound one, but not in the
    // infinite-token-only finding, which is reserved for apps that are otherwise scoped.
    expect(find(r, 'connected-app-full-scope')).toBeDefined();
    expect(find(r, 'connected-app-full-scope-infinite-token')).toBeDefined();
    expect(find(r, 'connected-app-infinite-refresh-token')).toBeUndefined();
  });

  it('separates a compound app from an unrelated infinite-token app', async () => {
    const r = await check.run(makeCtx([
      app('Worst', { scopes: ['Full'], validity: -1 }),
      app('Lax', { scopes: ['Api'], validity: -1 }),
    ]));
    expect(find(r, 'connected-app-infinite-refresh-token')!.affectedItems).toHaveLength(1);
    expect(find(r, 'connected-app-infinite-refresh-token')!.affectedItems?.[0].label).toBe('Lax');
    expect(find(r, 'connected-app-full-scope-infinite-token')!.affectedItems).toHaveLength(1);
  });

  it('reports the policy values so the setting can be found', async () => {
    const r = await check.run(makeCtx([app('Lax', { scopes: ['Api'], policy: 'infinite' })]));
    expect(find(r, 'connected-app-infinite-refresh-token')!.affectedItems?.[0].note)
      .toContain('infinite');
  });

  it('handles an app with null metadata without throwing', async () => {
    const r = await check.run(makeCtx([{ Id: '0Ci', Name: 'Bare', Metadata: null }]));
    expect(r.findings[0].id).toBe('connected-app-scope-ok');
  });
});
