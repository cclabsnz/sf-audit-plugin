import { jest } from '@jest/globals';
import { LightningMessageChannelCheck } from '../../../../src/checks/impl/LightningMessageChannelCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(records: unknown[]): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockResolvedValue(records),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: {},
  };
}

const channel = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Id: '1', DeveloperName: 'OrderUpdates', MasterLabel: 'Order Updates',
  NamespacePrefix: null, ManageableState: 'unmanaged', IsExposed: false, ...over,
});

describe('LightningMessageChannelCheck', () => {
  const check = new LightningMessageChannelCheck();

  it('passes when the org defines no message channels', async () => {
    const result = await check.run(makeCtx([]));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('lightning-message-channel-none');
    expect(result.findings[0].passed).toBe(true);
  });

  it('passes when every channel is scoped to its own namespace', async () => {
    const result = await check.run(makeCtx([channel(), channel({ Id: '2', DeveloperName: 'Refresh' })]));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('lightning-message-channel-ok');
    expect(result.findings[0].passed).toBe(true);
  });

  it('reports locally-defined exposed channels', async () => {
    const result = await check.run(makeCtx([
      channel({ IsExposed: true }),
      channel({ Id: '2', DeveloperName: 'Scoped', IsExposed: false }),
    ]));
    const finding = result.findings.find((f) => f.id === 'lightning-message-channel-exposed');
    expect(finding).toBeDefined();
    expect(finding!.riskLevel).toBe('MEDIUM');
    expect(finding!.affectedItems?.map((i) => i.label)).toEqual(['OrderUpdates']);
  });

  // isExposed cannot be set back to false, so a channel from an installed package has no
  // remediation available inside this org at all. Same reach, different owner: reported apart so a
  // reader is not handed a fix they cannot apply.
  it('separates installed exposed channels from local ones', async () => {
    const result = await check.run(makeCtx([
      channel({ IsExposed: true }),
      channel({ Id: '2', DeveloperName: 'VendorBus', NamespacePrefix: 'acme', ManageableState: 'installed', IsExposed: true }),
    ]));
    const local = result.findings.find((f) => f.id === 'lightning-message-channel-exposed');
    const installed = result.findings.find((f) => f.id === 'lightning-message-channel-exposed-installed');
    expect(local!.affectedItems?.map((i) => i.label)).toEqual(['OrderUpdates']);
    expect(installed!.affectedItems?.map((i) => i.label)).toEqual(['acme__VendorBus']);
    expect(installed!.riskLevel).toBe('LOW');
  });

  it('emits no local finding when every exposed channel is installed', async () => {
    const result = await check.run(makeCtx([
      channel({ ManageableState: 'installed', NamespacePrefix: 'acme', IsExposed: true }),
    ]));
    expect(result.findings.map((f) => f.id)).toEqual(['lightning-message-channel-exposed-installed']);
  });

  // Reversing isExposed is impossible, so remediation is a migration rather than a setting change.
  // Saying otherwise would understate the cost by a wide margin.
  it('states that the exposure cannot be reversed in place', async () => {
    const result = await check.run(makeCtx([channel({ IsExposed: true })]));
    const finding = result.findings.find((f) => f.id === 'lightning-message-channel-exposed')!;
    expect(finding.remediation).toContain('cannot be set back to false');
  });

  // Visualforce only supports exposed channels, so an exposed channel may be forced by the
  // platform rather than chosen. A reader told to "just turn it off" would be misled.
  it('notes that Visualforce requires exposed channels', async () => {
    const result = await check.run(makeCtx([channel({ IsExposed: true })]));
    const finding = result.findings.find((f) => f.id === 'lightning-message-channel-exposed')!;
    expect(finding.detail).toContain('Visualforce');
  });

  it('treats a missing ManageableState as locally defined', async () => {
    const result = await check.run(makeCtx([channel({ ManageableState: null, IsExposed: true })]));
    expect(result.findings.map((f) => f.id)).toEqual(['lightning-message-channel-exposed']);
  });
});
