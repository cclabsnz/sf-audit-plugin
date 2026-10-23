import { jest } from '@jest/globals';
import { TrustedIPRangesCheck } from '../../../../src/checks/impl/TrustedIPRangesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Trusted IP ranges come from SecuritySettings in the Metadata API; NetworkAccess is not served
// by the standard API and carries no range fields on the Tooling API.
function makeCtx(settings: unknown, { metadata = true } = {}): AuditContext {
  return {
    soql: { query: (jest.fn() as any).mockRejectedValue(new Error("sObject type 'NetworkAccess' is not supported.")) } as any,
    tooling: { query: (jest.fn() as any).mockRejectedValue(new Error("No such column 'StartAddress' on entity 'NetworkAccess'")) } as any,
    metadata: metadata
      ? {
          read: (jest.fn() as any).mockImplementation((type: string, name: string) =>
            type === 'SecuritySettings' && name === 'Security'
              ? settings instanceof Error ? Promise.reject(settings) : Promise.resolve(settings)
              : Promise.resolve(null),
          ),
        }
      : undefined,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

describe('TrustedIPRangesCheck', () => {
  const check = new TrustedIPRangesCheck();

  it('flags a range broader than /16 from the Metadata API settings', async () => {
    const r = await check.run(makeCtx({ networkAccess: { ipRanges: [{ start: '10.0.0.0', end: '10.255.255.255', description: 'corp' }, { start: '192.0.2.4', end: '192.0.2.4' }] } }));
    const broad = r.findings.find((f) => /broad|\/16/i.test(f.title) && f.riskLevel !== 'LOW');
    expect(broad?.affectedItems?.map((i) => i.label)).toEqual(['10.0.0.0–10.255.255.255']);
  });

  it('accepts a single range returned as an object', async () => {
    const r = await check.run(makeCtx({ networkAccess: { ipRanges: { start: '192.0.2.4', end: '192.0.2.5' } } }));
    expect(r.findings.some((f) => f.affectedItems?.some((i) => i.label === '192.0.2.4–192.0.2.5'))).toBe(true);
  });

  it('reports no ranges when the settings have none', async () => {
    const r = await check.run(makeCtx({ networkAccess: null }));
    expect(r.findings[0].id).toBe('trusted-ip-none');
  });

  it.each([
    ['the read fails', new Error('INSUFFICIENT_ACCESS')],
    ['the settings are not returned', null],
  ])('is inconclusive when %s', async (_l, settings) => {
    const r = await check.run(makeCtx(settings));
    expect(r.findings.map((f) => f.id)).toEqual(['trusted-ip-inaccessible']);
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('is inconclusive without a Metadata API client', async () => {
    const r = await check.run(makeCtx({}, { metadata: false }));
    expect(r.findings[0].id).toBe('trusted-ip-inaccessible');
  });
});
