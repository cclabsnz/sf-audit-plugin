import { jest } from '@jest/globals';
import { LegacyApiVersionCheck } from '../../../../src/checks/impl/LegacyApiVersionCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const apexClass = (name: string, apiVersion: number) => ({
  Id: `01p00000000${name}`,
  Name: name,
  ApiVersion: apiVersion,
});

// The check relies on the query's ORDER BY ApiVersion ASC, so the mock must return sorted rows
// for index 0 to be the oldest — the same contract the real query provides.
const classes = (versions: number[]) =>
  [...versions].sort((a, b) => a - b).map((v, i) => apexClass(`C${i}`, v));

const soapSite = (siteName: string, endpointUrl = 'https://old.example.com/services/Soap/u/21.0') => ({
  Id: `0rp00000000${siteName}`,
  SiteName: siteName,
  EndpointUrl: endpointUrl,
});

function makeCtx(opts: {
  apex?: unknown[];
  apexThrows?: boolean;
  soapSites?: unknown[];
  soapThrows?: boolean;
}): AuditContext {
  const query = jest.fn() as any;
  query.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM ApexClass')) {
      if (opts.apexThrows) throw new Error('no tooling access');
      return opts.apex ?? [];
    }
    if (soql.includes('FROM RemoteProxy')) {
      if (opts.soapThrows) throw new Error('unsupported LIKE on RemoteProxy');
      return opts.soapSites ?? [];
    }
    return [];
  });

  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query, getRecord: jest.fn() } as any,
    rest: { get: jest.fn() } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('LegacyApiVersionCheck', () => {
  const check = new LegacyApiVersionCheck();

  describe('Apex API versions', () => {
    it('passes when no class is below the threshold', async () => {
      const r = await check.run(makeCtx({ apex: [] }));
      const f = r.findings.find((x) => x.id === 'legacy-api-version-apex-ok');
      expect(f!.passed).toBe(true);
    });

    it('rates a class at or below v30 HIGH', async () => {
      const r = await check.run(makeCtx({ apex: classes([30, 45]) }));
      const f = r.findings.find((x) => x.id === 'legacy-api-version-apex');
      expect(f!.riskLevel).toBe('HIGH');
      expect(f!.title).toContain('oldest: v30');
    });

    it('rates an oldest version below v40 MEDIUM', async () => {
      const r = await check.run(makeCtx({ apex: classes([39]) }));
      expect(r.findings.find((x) => x.id === 'legacy-api-version-apex')!.riskLevel).toBe('MEDIUM');
    });

    it('rates more than ten classes MEDIUM even when each is recent enough', async () => {
      const r = await check.run(makeCtx({ apex: classes(Array.from({ length: 11 }, () => 45)) }));
      expect(r.findings.find((x) => x.id === 'legacy-api-version-apex')!.riskLevel).toBe('MEDIUM');
    });

    it('rates a few moderately old classes LOW', async () => {
      const r = await check.run(makeCtx({ apex: classes([45, 46]) }));
      const f = r.findings.find((x) => x.id === 'legacy-api-version-apex');
      expect(f!.riskLevel).toBe('LOW');
      expect(f!.passed).toBeFalsy();
    });

    it('says 50+ when the query hit its limit, rather than claiming exactly fifty', async () => {
      const r = await check.run(makeCtx({ apex: classes(Array.from({ length: 50 }, () => 45)) }));
      expect(r.findings.find((x) => x.id === 'legacy-api-version-apex')!.title).toContain('50+');
    });

    it('reports the exact count below the limit', async () => {
      const r = await check.run(makeCtx({ apex: classes([45, 46, 47]) }));
      expect(r.findings.find((x) => x.id === 'legacy-api-version-apex')!.title).toContain('3 custom');
    });

    it('names each class with its API version', async () => {
      const r = await check.run(makeCtx({ apex: classes([33]) }));
      const items = r.findings.find((x) => x.id === 'legacy-api-version-apex')!.affectedItems!;
      expect(items[0].note).toBe('API v33');
    });
  });

  describe('SOAP remote sites', () => {
    it('emits nothing when there are none', async () => {
      const r = await check.run(makeCtx({ soapSites: [] }));
      expect(r.findings.some((x) => x.id === 'legacy-api-soap-remote-sites')).toBe(false);
    });

    it('reports them at MEDIUM when present', async () => {
      const r = await check.run(makeCtx({ soapSites: [soapSite('LegacyPartner')] }));
      const f = r.findings.find((x) => x.id === 'legacy-api-soap-remote-sites');
      expect(f!.riskLevel).toBe('MEDIUM');
      expect(f!.affectedItems![0].note).toContain('/services/Soap/');
    });

    it('is inconclusive when RemoteProxy cannot be queried', async () => {
      // The LIKE predicate is not supported on RemoteProxy in every edition, so this query
      // legitimately fails. Skipping silently left no trace: the absence of a SOAP finding is
      // indistinguishable from having established there are no SOAP remote sites. The sibling
      // RemoteSitesCheck covers remote sites in general and makes no SOAP determination, so it
      // does not cover for this one.
      const r = await check.run(makeCtx({ soapThrows: true }));
      const f = r.findings.find((x) => x.inconclusive);
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('INFO');
      expect(f!.passed).toBeFalsy();
    });

    it('still reports the Apex findings when RemoteProxy fails', async () => {
      const r = await check.run(makeCtx({ apex: classes([30]), soapThrows: true }));
      expect(r.findings.find((x) => x.id === 'legacy-api-version-apex')!.riskLevel).toBe('HIGH');
    });
  });

  describe('inbound SOAP advisory', () => {
    it('is always emitted, as INFO, and carries no penalty', async () => {
      const r = await check.run(makeCtx({}));
      const f = r.findings.find((x) => x.id === 'legacy-api-soap-inbound-advisory');
      expect(f).toBeDefined();
      // INFO scores zero in the default config, so an unconditional advisory does not cost the
      // org anything. It is guidance, not a finding against the org.
      expect(f!.riskLevel).toBe('INFO');
    });
  });

  it('propagates a failure to read Apex classes', async () => {
    // Without the class list there is nothing to assert about API versions, so the engine should
    // record an errored check rather than the report claiming every class is current.
    await expect(check.run(makeCtx({ apexThrows: true }))).rejects.toThrow();
  });
});
