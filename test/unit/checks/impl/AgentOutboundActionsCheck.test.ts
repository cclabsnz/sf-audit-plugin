import { jest } from '@jest/globals';
import { AgentOutboundActionsCheck } from '../../../../src/checks/impl/AgentOutboundActionsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AgentDefinition } from '@cclabsnz/sf-core';

function makeCtx(opts: {
  agentInventory?: AgentDefinition[];
  agentAccess?: 'ok' | 'not-enabled' | 'unknown';
  functions?: unknown[] | Error;
  pluginActions?: unknown[] | Error;
}): AuditContext {
  const pick = (v: unknown[] | Error | undefined) =>
    v instanceof Error ? Promise.reject(v) : Promise.resolve(v ?? []);
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) => {
        if (/FROM GenAiPluginFunctionDef/i.test(soql)) return pick(opts.pluginActions);
        if (/FROM GenAiFunctionDefinition/i.test(soql)) return pick(opts.functions);
        return Promise.resolve([]);
      }),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: { agentInventory: opts.agentInventory, agentAccess: opts.agentAccess },
  } as any;
}

function agent(overrides: Partial<AgentDefinition> = {}): AgentDefinition {
  return { developerName: 'SalesAgent', label: 'Sales Agent', type: 'agent', isActive: true, activeVersion: 1, ...overrides };
}

function fn(overrides: Record<string, unknown>) {
  return {
    Id: 'F1', DeveloperName: 'Action', MasterLabel: 'Action', Source: null,
    InvocationTargetType: 'flow', InvocationTarget: 'Something', IsConfirmationRequired: false,
    ...overrides,
  };
}

describe('AgentOutboundActionsCheck', () => {
  const check = new AgentOutboundActionsCheck();

  it('declares its identity and cache contract', () => {
    expect(check.id).toBe('agent-outbound-actions');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['agentInventory', 'agentAccess']));
  });

  it('is silent when agentAccess is not ok', async () => {
    const ctx = makeCtx({ agentAccess: 'not-enabled', agentInventory: [agent()], functions: new Error('should not query') });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('is silent with no active agents', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent({ isActive: false })],
      functions: [fn({ InvocationTargetType: 'slack', InvocationTarget: 'postMessage' })],
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('flags HIGH for unconfirmed Slack, email and external actions', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [
        fn({ Id: 'F1', MasterLabel: 'Reply in Thread', Source: 'Slack__ReplyInThread', InvocationTargetType: 'slack' }),
        fn({ Id: 'F2', MasterLabel: 'Notify Customer', InvocationTargetType: 'standardInvocableAction', InvocationTarget: 'emailSimple' }),
        fn({ Id: 'F3', MasterLabel: 'Partner Lookup', InvocationTargetType: 'externalService', InvocationTarget: 'PartnerApi.lookup' }),
        fn({ Id: 'F4', MasterLabel: 'Summarise', InvocationTargetType: 'flow', InvocationTarget: 'Summarise' }),
      ],
    });
    const { findings } = await check.run(ctx);
    const high = findings.find((f) => f.id === 'agent-outbound-actions-unconfirmed');
    expect(high).toBeDefined();
    expect(high!.riskLevel).toBe('HIGH');
    expect(high!.affectedItems!.map((i) => i.label)).toEqual(['Reply in Thread', 'Notify Customer', 'Partner Lookup']);
  });

  it('does not flag outbound actions that require confirmation', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [fn({ Source: 'Slack__SendMessageToSlackChannel', InvocationTargetType: 'slack', IsConfirmationRequired: true })],
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('recognises a Send…Email action by name', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [fn({ DeveloperName: 'SendClaimEmail', MasterLabel: 'Send Claim Email', InvocationTargetType: 'apex', InvocationTarget: 'ClaimMailer' })],
    });
    expect((await check.run(ctx)).findings.map((f) => f.id)).toEqual(['agent-outbound-actions-unconfirmed']);
  });

  it('does not treat drafting an email as sending one', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [fn({ Source: 'EmployeeCopilot__DraftOrReviseEmail', InvocationTargetType: 'standardInvocableAction', InvocationTarget: 'draftOrReviseEmail' })],
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('reports MEDIUM unverified for standard outbound actions seen only as topic links', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [],
      pluginActions: [
        { PluginId: '179A', Function: 'Slack__SendMessageAsAgent' },
        { PluginId: '179A', Function: 'EmployeeCopilot__QueryRecords' },
      ],
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-outbound-actions-unverified']);
    expect(findings[0].riskLevel).toBe('MEDIUM');
  });

  it('does not double-report a standard action that also has a definition row', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      functions: [fn({ Source: 'Slack__ReplyInThread', InvocationTargetType: 'slack', IsConfirmationRequired: true })],
      pluginActions: [{ PluginId: '179A', Function: 'Slack__ReplyInThread' }],
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('degrades silently when the function object is missing', async () => {
    const err = Object.assign(new Error('INVALID_TYPE'), { errorCode: 'INVALID_TYPE', statusCode: 400 });
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent()], functions: err, pluginActions: err });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });
});
