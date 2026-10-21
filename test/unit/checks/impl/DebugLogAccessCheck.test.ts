import { jest } from '@jest/globals';
import { DebugLogAccessCheck } from '../../../../src/checks/impl/DebugLogAccessCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(traces: unknown[] | Error): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        traces instanceof Error ? Promise.reject(traces) : Promise.resolve(traces),
      ),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

describe('DebugLogAccessCheck', () => {
  const check = new DebugLogAccessCheck();

  it('queries TraceFlag through the Tooling API, the only API that serves it', async () => {
    const ctx = makeCtx([]);
    const r = await check.run(ctx);
    expect((ctx.soql.query as any).mock.calls).toHaveLength(0);
    expect((ctx.tooling.query as any).mock.calls[0][0]).toMatch(/FROM TraceFlag/);
    expect(r.findings[0].id).toBe('debug-log-none');
  });

  it('flags a high-detail trace', async () => {
    const r = await check.run(makeCtx([
      { Id: '7tf1', TracedEntityId: '005A', LogType: 'USER_DEBUG', ExpirationDate: '2099-01-01T00:00:00Z', DebugLevel: { DeveloperName: 'X', ApexCode: 'FINEST' } },
    ]));
    expect(r.findings.some((f) => f.id === 'debug-log-high-level')).toBe(true);
  });

  it('is inconclusive and quotes the error when TraceFlag cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings[0].id).toBe('debug-log-inaccessible');
    expect(r.findings[0].detail).toContain('INSUFFICIENT_ACCESS');
  });
});
