import { jest } from '@jest/globals';
import { OutboundMessagesCheck } from '../../../../src/checks/impl/OutboundMessagesCheck.js';
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

describe('OutboundMessagesCheck', () => {
  const check = new OutboundMessagesCheck();

  it('flags messages that include the session ID as HIGH', async () => {
    const ctx = makeCtx([{ Id: '1', Name: 'NotifyERP', EndpointUrl: 'https://erp.acme.com/hook', IncludeSessionId: true }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'outbound-messages-session-id');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags cleartext http endpoints as HIGH', async () => {
    const ctx = makeCtx([{ Id: '1', Name: 'NotifyERP', EndpointUrl: 'http://erp.acme.com/hook', IncludeSessionId: false }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'outbound-messages-cleartext');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('passes inventory when endpoints are HTTPS without session ID', async () => {
    const ctx = makeCtx([{ Id: '1', Name: 'NotifyERP', EndpointUrl: 'https://erp.acme.com/hook', IncludeSessionId: false }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'outbound-messages-inventory');
    expect(f!.passed).toBe(true);
  });

  it('passes when no outbound messages exist', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'outbound-messages-none' && f.passed)).toBe(true);
  });

  it('is inconclusive when the object is not accessible', async () => {
    const ctx = makeCtx([], true);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
