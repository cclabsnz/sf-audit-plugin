import { jest } from '@jest/globals';
import { PublicContentExposureCheck } from '../../../../src/checks/impl/PublicContentExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: {
  documents?: unknown[] | Error;
  resources?: unknown[] | Error;
}): AuditContext {
  const resolve = (v: unknown[] | Error | undefined): unknown[] => {
    if (v instanceof Error) throw v;
    return v ?? [];
  };
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation(async () => resolve(opts.documents)),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(async () => resolve(opts.resources)),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('PublicContentExposureCheck', () => {
  const check = new PublicContentExposureCheck();

  it('flags externally available Documents as HIGH', async () => {
    const ctx = makeCtx({ documents: [{ Id: '1', Name: 'export.csv', IsPublic: true, Folder: { Name: 'Shared' } }] });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'public-content-public-documents');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags Public static resources as MEDIUM', async () => {
    const ctx = makeCtx({ resources: [{ Id: '1', Name: 'config', CacheControl: 'Public', ContentType: 'application/json' }] });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'public-content-public-static-resources');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes when nothing is public', async () => {
    const ctx = makeCtx({ documents: [], resources: [] });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'public-content-documents-ok' && f.passed)).toBe(true);
    expect(result.findings.some((f) => f.id === 'public-content-static-resources-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when Documents are not accessible', async () => {
    const ctx = makeCtx({ documents: Object.assign(new Error('no access'), { errorCode: 'ENTITY_IS_INACCESSIBLE' }), resources: [] });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'public-content-documents-inaccessible' && f.inconclusive)).toBe(true);
  });
});
