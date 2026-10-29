import { jest } from '@jest/globals';
import { FlowsWithoutSharingCheck } from '../../../../src/checks/impl/FlowsWithoutSharingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const flow = (processType: string, runInMode: string | null, label = `${processType}-${runInMode}`) =>
  ({ Id: `301${label}`, MasterLabel: label, ProcessType: processType, Status: 'Active', RunInMode: runInMode });

function ctxWith(rows: unknown[]): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query: (jest.fn() as any).mockResolvedValue(rows) } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('FlowsWithoutSharingCheck', () => {
  const check = new FlowsWithoutSharingCheck();

  // Only the explicit "without sharing" setting skips sharing. In Default Mode a screen flow runs as
  // the user and an autolaunched flow in its caller's context.
  it('flags flows set to run in system context without sharing', async () => {
    const r = await check.run(ctxWith([flow('AutoLaunchedFlow', 'SystemModeWithoutSharing'), flow('Flow', 'SystemModeWithoutSharing')]));
    expect(r.findings.find((f) => f.id === 'flows-autolaunched-without-sharing')!.riskLevel).toBe('HIGH');
    expect(r.findings.find((f) => f.id === 'flows-screen-without-sharing')!.riskLevel).toBe('MEDIUM');
  });

  it.each(['DefaultMode', null, 'SystemModeWithSharing'])('does not flag flows whose run mode is %s', async (mode) => {
    const r = await check.run(ctxWith([flow('AutoLaunchedFlow', mode), flow('Flow', mode)]));
    expect(r.findings.map((f) => f.id)).toEqual(['flows-without-sharing-none']);
    expect(r.findings[0].passed).toBe(true);
  });
});
