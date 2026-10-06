import { jest } from '@jest/globals';
import { NamedCredentialsCheck } from '../../../../src/checks/impl/NamedCredentialsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const cred = (
  developerName: string,
  opts: { label?: string; endpoint?: string | null; principalType?: string | null } = {}
) => ({
  Id: `0XA000000000${developerName.slice(0, 3)}`,
  MasterLabel: opts.label ?? developerName,
  DeveloperName: developerName,
  Endpoint: opts.endpoint === undefined ? 'https://api.example.com' : opts.endpoint,
  PrincipalType: opts.principalType ?? 'NamedUser',
});

function makeCtx(opts: {
  creds?: unknown[];
  credsThrow?: boolean;
  apexBodies?: Array<{ name: string; body: string }>;
  apexListThrows?: boolean;
  cache?: Record<string, unknown>;
}): AuditContext {
  const query = jest.fn() as any;
  query.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM NamedCredential')) {
      if (opts.credsThrow) throw new Error('no tooling access');
      return opts.creds ?? [];
    }
    // ApexRepository.listClasses goes through the same tooling client.
    if (opts.apexListThrows) throw new Error('no ApexClass access');
    return (opts.apexBodies ?? []).map((b) => ({ Name: b.name, Body: b.body, NamespacePrefix: null }));
  });

  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query, getRecord: jest.fn() } as any,
    rest: { get: jest.fn() } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: opts.cache ?? {},
  } as any;
}

describe('NamedCredentialsCheck', () => {
  const check = new NamedCredentialsCheck();

  it('reports no credentials and zero metrics when none are configured', async () => {
    const r = await check.run(makeCtx({ creds: [] }));
    expect(r.findings[0].id).toBe('named-credentials-none');
    expect(r.metrics).toEqual({ namedCredentialsCount: 0, unusedNamedCredentialsCount: 0 });
  });

  it('caches endpoints for HardcodedCredentialsCheck, dropping the null ones', async () => {
    const ctx = makeCtx({
      creds: [cred('A'), cred('B', { endpoint: null })],
      cache: { apexBodies: [{ name: 'X', body: 'callout:A callout:B' }] },
    });
    await check.run(ctx);
    expect(ctx.cache.namedCredentialEndpoints).toEqual(['https://api.example.com']);
  });

  it('counts a credential referenced by developer name as used', async () => {
    const r = await check.run(
      makeCtx({ creds: [cred('MyService')], cache: { apexBodies: [{ name: 'X', body: "req.setEndpoint('callout:MyService/path');" }] } })
    );
    expect(r.findings.some((f) => f.id === 'named-credentials-unused')).toBe(false);
    expect(r.metrics!.unusedNamedCredentialsCount).toBe(0);
  });

  it('counts a credential referenced by underscored label as used', async () => {
    const r = await check.run(
      makeCtx({
        creds: [cred('svc_dev', { label: 'My Service' })],
        cache: { apexBodies: [{ name: 'X', body: 'callout:My_Service' }] },
      })
    );
    expect(r.findings.some((f) => f.id === 'named-credentials-unused')).toBe(false);
  });

  it('flags a credential no Apex references', async () => {
    const r = await check.run(
      makeCtx({ creds: [cred('Orphan')], cache: { apexBodies: [{ name: 'X', body: 'nothing here' }] } })
    );
    const f = r.findings.find((x) => x.id === 'named-credentials-unused');
    expect(f!.riskLevel).toBe('LOW');
    expect(r.metrics!.unusedNamedCredentialsCount).toBe(1);
  });

  it('flags a plaintext HTTP endpoint at HIGH (SBS-INT-003)', async () => {
    const r = await check.run(
      makeCtx({
        creds: [cred('Legacy', { endpoint: 'http://insecure.example.com' })],
        cache: { apexBodies: [{ name: 'X', body: 'callout:Legacy' }] },
      })
    );
    const f = r.findings.find((x) => x.id === 'named-credentials-http-endpoint');
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('does not mistake an https endpoint for a plaintext one', async () => {
    const r = await check.run(
      makeCtx({ creds: [cred('Secure')], cache: { apexBodies: [{ name: 'X', body: 'callout:Secure' }] } })
    );
    expect(r.findings.some((x) => x.id === 'named-credentials-http-endpoint')).toBe(false);
  });

  it('flags an anonymous principal type', async () => {
    const r = await check.run(
      makeCtx({
        creds: [cred('Public', { principalType: 'Anonymous' })],
        cache: { apexBodies: [{ name: 'X', body: 'callout:Public' }] },
      })
    );
    expect(r.findings.find((x) => x.id === 'named-credentials-anonymous')!.riskLevel).toBe('LOW');
  });

  it('describes an External Credential entry rather than printing its null endpoint', async () => {
    const r = await check.run(
      makeCtx({ creds: [cred('ExtCred', { endpoint: null, principalType: 'Anonymous' })], cache: { apexBodies: [{ name: 'X', body: '' }] } })
    );
    // Endpoint is nullable for External Credential-backed entries. Every note that renders it
    // must say so, not interpolate the word "null" into advice shown to an operator.
    for (const f of r.findings) {
      for (const item of f.affectedItems ?? []) {
        expect(item.note ?? '').not.toContain('null');
      }
    }
  });

  describe('when Apex cannot be scanned', () => {
    const ctxOpts = {
      creds: [
        cred('Legacy', { endpoint: 'http://insecure.example.com' }),
        cred('Public', { principalType: 'Anonymous' }),
      ],
      apexListThrows: true,
    };

    it('still reports the inventory', async () => {
      const r = await check.run(makeCtx(ctxOpts));
      expect(r.findings.some((f) => f.id === 'named-credentials-inventory')).toBe(true);
    });

    it('does not claim anything about which credentials are unused', async () => {
      const r = await check.run(makeCtx(ctxOpts));
      expect(r.findings.some((f) => f.id === 'named-credentials-unused')).toBe(false);
    });

    it('still flags the plaintext HTTP endpoint', async () => {
      // The HTTP finding is derived entirely from the credential records, which were read
      // successfully. Returning early on the Apex failure discarded a HIGH finding that was
      // fully established — the Apex scan only ever informed the unused analysis.
      const r = await check.run(makeCtx(ctxOpts));
      const f = r.findings.find((x) => x.id === 'named-credentials-http-endpoint');
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('HIGH');
    });

    it('still flags the anonymous principal type', async () => {
      const r = await check.run(makeCtx(ctxOpts));
      expect(r.findings.some((x) => x.id === 'named-credentials-anonymous')).toBe(true);
    });

    it('says the unused analysis did not run', async () => {
      const r = await check.run(makeCtx(ctxOpts));
      const f = r.findings.find((x) => x.inconclusive);
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('INFO');
    });

    it('does not report a count of unused credentials it did not compute', async () => {
      const r = await check.run(makeCtx(ctxOpts));
      // Zero here is indistinguishable from "none are unused", which was never established.
      expect(r.metrics!.unusedNamedCredentialsCount).toBeUndefined();
    });
  });

  it('propagates a failure to read the credentials themselves', async () => {
    await expect(check.run(makeCtx({ credsThrow: true }))).rejects.toThrow();
  });
});
