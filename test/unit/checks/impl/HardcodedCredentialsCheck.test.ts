import { jest } from '@jest/globals';
import { HardcodedCredentialsCheck } from '../../../../src/checks/impl/HardcodedCredentialsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

/** ApexRepository.listClasses issues one tooling query against ApexClass. */
const apexClass = (Name: string, Body: string, NamespacePrefix: string | null = null) =>
  ({ Name, NamespacePrefix, Body, SymbolTable: null });

function makeCtx(classes: unknown[], cache: Record<string, unknown> = {}): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() => Promise.resolve(classes)),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { ...cache } as any,
  } as any;
}

// Long enough to clear the minimum-length guards that keep test stubs out of the results.
const BEARER = 'Bearer abcdefghijklmnopqrstuvwxyz0123456789';
const BASIC = 'Basic YWRtaW46c3VwZXJzZWNyZXRwYXNzd29yZA==';

describe('HardcodedCredentialsCheck', () => {
  const check = new HardcodedCredentialsCheck();

  it('declares its cache contract in both directions', () => {
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['namedCredentialEndpoints', 'remoteSiteUrls']),
    );
    expect(check.populatesCache).toEqual(expect.arrayContaining(['apexBodies']));
  });

  it('passes when nothing suspicious is present', async () => {
    const ctx = makeCtx([apexClass('Clean', 'public class Clean { }')]);
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
    expect(r.findings[0].passed).toBe(true);
    expect(r.findings[0].detail).toContain('1 custom Apex classes');
  });

  it.each([
    ['a Bearer token', `String h = '${BEARER}';`],
    ['Basic auth', `String h = '${BASIC}';`],
    ['an Authorization header literal', `String h = '{"Authorization": "Bearer xyz"}';`],
    ['a password assignment', `String password = 'hunter2hunter2';`],
    ['a client secret assignment', `String client_secret = 'abcdefghijkl';`],
    ['an api key assignment', `String apiKey = 'k9sdf7sdf8sdf';`],
  ])('detects %s', async (_label, body) => {
    const ctx = makeCtx([apexClass('Leaky', `public class Leaky { ${body} }`)]);
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'hardcoded-credentials-found');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toBe('Leaky');
  });

  // Apex's usual idiom is `req.setHeader('Authorization', 'Bearer ' + token)`. The comma stops
  // the Authorization pattern matching, which is right: a token held in a variable is not a
  // hardcoded credential. Detection there depends on the Bearer/Basic patterns instead, and
  // only when the literal is long enough to be a real secret.
  it('does not flag an Authorization header built from a variable', async () => {
    const ctx = makeCtx([apexClass('Ok', `req.setHeader('Authorization', 'Bearer ' + token);`)]);
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
  });

  it('flags the same idiom when the token is inlined', async () => {
    const ctx = makeCtx([apexClass('Bad', `req.setHeader('Authorization', '${'Bearer abcdefghijklmnopqrstuvwxyz0123456789'}');`)]);
    const r = await check.run(ctx);
    expect(r.findings.some((x) => x.id === 'hardcoded-credentials-found')).toBe(true);
  });

  it('ignores short values that are more likely stubs than secrets', async () => {
    const ctx = makeCtx([apexClass('Stub', "public class Stub { String password = 'abc'; }")]);
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
  });

  // Test classes are excluded from the scan and from the cache, so fixtures full of fake
  // credentials do not become findings.
  it('excludes @IsTest classes from scanning', async () => {
    const ctx = makeCtx([
      apexClass('MyTest', `@IsTest public class MyTest { String password = 'hunter2hunter2'; }`),
    ]);
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
    // ...and reports zero scanned classes, not one.
    expect(r.findings[0].detail).toContain('0 custom Apex classes');
  });

  it('populates the apexBodies cache with non-test classes only', async () => {
    const ctx = makeCtx([
      apexClass('Real', 'public class Real { }'),
      apexClass('RealTest', '@IsTest public class RealTest { }'),
    ]);
    await check.run(ctx);
    const cached = (ctx.cache as any).apexBodies as Array<{ name: string }>;
    expect(cached.map((c) => c.name)).toEqual(['Real']);
  });

  it('flags a raw endpoint covered by nothing as MEDIUM', async () => {
    const ctx = makeCtx(
      [apexClass('Caller', "req.setEndpoint('https://api.vendor.com/v1/data');")],
      { namedCredentialEndpoints: [], remoteSiteUrls: [] },
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'raw-endpoints-uncovered');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('does not flag an endpoint already covered by a Named Credential', async () => {
    const ctx = makeCtx(
      [apexClass('Caller', "req.setEndpoint('https://api.vendor.com/v1/data');")],
      { namedCredentialEndpoints: ['https://api.vendor.com'], remoteSiteUrls: [] },
    );
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
  });

  it('downgrades to LOW when only a Remote Site covers the endpoint', async () => {
    const ctx = makeCtx(
      [apexClass('Caller', "req.setEndpoint('https://api.vendor.com/v1/data');")],
      { namedCredentialEndpoints: [], remoteSiteUrls: ['https://api.vendor.com'] },
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'raw-endpoints-remote-site-only');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('LOW');
    expect(r.findings.some((x) => x.id === 'raw-endpoints-uncovered')).toBe(false);
  });

  it('matches coverage on host, not on the full path', async () => {
    const ctx = makeCtx(
      [apexClass('Caller', "req.setEndpoint('https://api.vendor.com/some/deep/path?q=1');")],
      { namedCredentialEndpoints: ['https://api.vendor.com'], remoteSiteUrls: [] },
    );
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('no-hardcoded-credentials');
  });

  it('reports a class once as uncovered when it has both covered and uncovered endpoints', async () => {
    const ctx = makeCtx(
      [apexClass('Mixed', [
        "req.setEndpoint('https://known.com/a');",
        "req.setEndpoint('https://unknown.com/b');",
      ].join('\n'))],
      { namedCredentialEndpoints: ['https://known.com'], remoteSiteUrls: [] },
    );
    const r = await check.run(ctx);
    // Uncovered wins: the class still has an unmanaged callout.
    expect(r.findings.find((x) => x.id === 'raw-endpoints-uncovered')!.affectedItems)
      .toHaveLength(1);
    expect(r.findings.some((x) => x.id === 'raw-endpoints-remote-site-only')).toBe(false);
  });

  it('handles a missing cache without throwing', async () => {
    const ctx = makeCtx([apexClass('Caller', "req.setEndpoint('https://api.vendor.com/x');")]);
    const r = await check.run(ctx);
    expect(r.findings.some((x) => x.id === 'raw-endpoints-uncovered')).toBe(true);
  });

  it('reports credentials and endpoints independently', async () => {
    const ctx = makeCtx([
      apexClass('Leaky', `String h = '${BEARER}';`),
      apexClass('Caller', "req.setEndpoint('https://api.vendor.com/x');"),
    ]);
    const r = await check.run(ctx);
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain('hardcoded-credentials-found');
    expect(ids).toContain('raw-endpoints-uncovered');
    expect(ids).not.toContain('no-hardcoded-credentials');
  });

  // The patterns are module-level regexes with the /g flag, whose lastIndex persists between
  // uses. If it were not reset, the second class scanned would be matched from the wrong
  // offset and silently missed.
  it('detects the same pattern in consecutive classes', async () => {
    const ctx = makeCtx([
      apexClass('One', `String h = '${BEARER}';`),
      apexClass('Two', `String h = '${BEARER}';`),
    ]);
    const r = await check.run(ctx);
    expect(r.findings.find((x) => x.id === 'hardcoded-credentials-found')!.affectedItems)
      .toHaveLength(2);
  });

  it('excludes managed-package classes at the query level', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    const q = (ctx.tooling.query as any).mock.calls[0][0] as string;
    expect(q).toMatch(/FROM ApexClass/i);
    expect(q).toMatch(/NamespacePrefix\s*=\s*null/i);
  });
});
