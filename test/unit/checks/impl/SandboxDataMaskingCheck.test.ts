import { jest } from '@jest/globals';
import { SandboxDataMaskingCheck } from '../../../../src/checks/impl/SandboxDataMaskingCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(opts: { isSandbox: boolean; totalSize?: number; queryThrow?: boolean }): AuditContext {
  const query = jest.fn() as any;
  query.mockImplementation(async () => {
    if (opts.queryThrow) throw new Error('no object');
    return { totalSize: opts.totalSize ?? 0, done: true, records: [] };
  });
  return {
    soql: { query, queryAll: jest.fn() } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: opts.isSandbox, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('SandboxDataMaskingCheck', () => {
  const check = new SandboxDataMaskingCheck();

  it('passes as not-applicable in a production org', async () => {
    const r = await check.run(makeCtx({ isSandbox: false }));
    expect(r.findings.some((f) => f.id === 'sandbox-data-masking-na' && f.passed)).toBe(true);
  });

  it('flags populated PII in a sandbox as MEDIUM', async () => {
    const r = await check.run(makeCtx({ isSandbox: true, totalSize: 500 }));
    expect(r.findings.find((f) => f.id === 'sandbox-data-masking-pii-present')?.riskLevel).toBe('MEDIUM');
  });

  it('passes when a sandbox has no populated PII', async () => {
    const r = await check.run(makeCtx({ isSandbox: true, totalSize: 0 }));
    expect(r.findings.some((f) => f.id === 'sandbox-data-masking-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when PII probes cannot run', async () => {
    const r = await check.run(makeCtx({ isSandbox: true, queryThrow: true }));
    expect(r.findings[0].id).toBe('sandbox-data-masking-inconclusive');
  });
});
