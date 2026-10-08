import { jest } from '@jest/globals';
import { AgentOutboundActionsCheck } from '../../../../src/checks/impl/AgentOutboundActionsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AgentDefinition } from '@cclabsnz/sf-core';

type Tables = Partial<Record<
  'planners' | 'plannerTopics' | 'plugins' | 'pluginActions' | 'functions' | 'flowDefinitions' | 'flows',
  unknown[] | Error
>>;

// Routes each Tooling query to a table by its FROM clause; Flow lookups filter by Id.
function makeCtx(opts: { agentInventory?: AgentDefinition[]; agentAccess?: 'ok' | 'not-enabled' | 'unknown'; tables?: Tables }): AuditContext {
  const t = opts.tables ?? {};
  const pick = (v: unknown[] | Error | undefined) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(v ?? []));
  const byId = (rows: unknown[] | Error | undefined, soql: string) => {
    if (rows instanceof Error) return Promise.reject(rows);
    const id = /Id = '([^']+)'/.exec(soql)?.[1];
    const name = /DeveloperName = '([^']+)'/.exec(soql)?.[1];
    return Promise.resolve((rows ?? []).filter((r: any) => (id ? r.Id === id : r.DeveloperName === name)));
  };
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) => {
        if (/FROM GenAiPlannerFunctionDef/i.test(soql)) return pick(t.plannerTopics);
        if (/FROM GenAiPlannerDefinition/i.test(soql)) return pick(t.planners);
        if (/FROM GenAiPluginFunctionDef/i.test(soql)) return pick(t.pluginActions);
        if (/FROM GenAiPluginDefinition/i.test(soql)) return pick(t.plugins);
        if (/FROM GenAiFunctionDefinition/i.test(soql)) return pick(t.functions);
        if (/FROM FlowDefinition/i.test(soql)) return byId(t.flowDefinitions, soql);
        if (/FROM Flow\b/i.test(soql)) return byId(t.flows, soql);
        return Promise.resolve([]);
      }),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'org1', name: 'Test', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://test.salesforce.com' },
    cache: { agentInventory: opts.agentInventory, agentAccess: opts.agentAccess },
  } as any;
}

function agent(overrides: Partial<AgentDefinition> = {}): AgentDefinition {
  return { developerName: 'SalesAgent', label: 'Sales Agent', type: 'agent', isActive: true, activeVersion: 2, ...overrides };
}

// One active agent (planner SalesAgent_v2) with one topic; actions attach to that topic.
const planners = [
  { Id: '16jV1', DeveloperName: 'SalesAgent_v1', MasterLabel: 'Sales Agent' },
  { Id: '16jV2', DeveloperName: 'SalesAgent_v2', MasterLabel: 'Sales Agent' },
];
const plugins = [
  { Id: '179T1', DeveloperName: 'GeneralCRM_16jV1', MasterLabel: 'General CRM', Source: null, PlannerId: '16jV1' },
  { Id: '179T2', DeveloperName: 'GeneralCRM_16jV2', MasterLabel: 'General CRM', Source: null, PlannerId: '16jV2' },
];
function fn(overrides: Record<string, unknown>) {
  return {
    Id: '172F1', DeveloperName: 'Action', MasterLabel: 'Action', Source: null, PlannerId: null, PluginId: '179T2',
    InvocationTargetType: 'flow', InvocationTarget: 'Something', IsConfirmationRequired: false,
    ...overrides,
  };
}
const live = (functions: unknown[], extra: Tables = {}): Tables => ({ planners, plugins, functions, ...extra });

describe('AgentOutboundActionsCheck', () => {
  const check = new AgentOutboundActionsCheck();

  it('declares its identity and cache contract', () => {
    expect(check.id).toBe('agent-outbound-actions');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['agentInventory', 'agentAccess']));
  });

  it('is silent when agentAccess is not ok', async () => {
    const ctx = makeCtx({ agentAccess: 'not-enabled', agentInventory: [agent()], tables: { planners: new Error('should not query') } });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('is silent with no active agents', async () => {
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent({ isActive: false })], tables: live([fn({ InvocationTargetType: 'slack' })]) });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('flags HIGH for unconfirmed Slack, email and external actions on the active version', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([
        fn({ Id: '172A', MasterLabel: 'Reply in Thread', Source: 'Slack__ReplyInThread', InvocationTargetType: 'slack' }),
        fn({ Id: '172B', MasterLabel: 'Notify Customer', InvocationTargetType: 'standardInvocableAction', InvocationTarget: 'emailSimple' }),
        fn({ Id: '172C', MasterLabel: 'Partner Lookup', InvocationTargetType: 'externalService', InvocationTarget: 'PartnerApi.lookup' }),
        fn({ Id: '172D', MasterLabel: 'Summarise', InvocationTargetType: 'standardInvocableAction', InvocationTarget: 'getDataForGrounding' }),
      ]),
    });
    const high = (await check.run(ctx)).findings.find((f) => f.id === 'agent-outbound-actions-unconfirmed');
    expect(high!.riskLevel).toBe('HIGH');
    expect(high!.affectedItems!.map((i) => i.label).sort()).toEqual(['Notify Customer', 'Partner Lookup', 'Reply in Thread']);
  });

  it('ignores actions that only exist on an inactive agent version', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([fn({ PluginId: '179T1', InvocationTargetType: 'slack' })]),
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('does not flag outbound actions that require confirmation', async () => {
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent()], tables: live([fn({ Source: 'Slack__SendMessageToSlackChannel', InvocationTargetType: 'slack', IsConfirmationRequired: true })]) });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('does not treat drafting an email as sending one', async () => {
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent()], tables: live([fn({ Source: 'EmployeeCopilot__DraftOrReviseEmail', InvocationTargetType: 'standardInvocableAction', InvocationTarget: 'getDraftOrReviseEmailPrompt' })]) });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('flags a Flow action whose active flow version sends email', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live(
        [fn({ MasterLabel: 'Notify Lead By Email', DeveloperName: 'Notify_Lead_By_Email_179T2', InvocationTargetType: 'flow', InvocationTarget: '300000000000001AAA' })],
        {
          flowDefinitions: [{ Id: '300000000000001AAA', DeveloperName: 'Send_Lead_Email', ActiveVersionId: '301000000000001AAA' }],
          flows: [{ Id: '301000000000001AAA', Metadata: { actionCalls: [{ actionType: 'emailSimple', actionName: 'emailSimple' }] } }],
        },
      ),
    });
    const high = (await check.run(ctx)).findings.find((f) => f.id === 'agent-outbound-actions-unconfirmed');
    expect(high!.affectedItems).toEqual([expect.objectContaining({ label: 'Notify Lead By Email', note: 'email (flow Send_Lead_Email), no confirmation required' })]);
  });

  it('does not flag a Flow action whose flow only reads data', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([fn({ InvocationTargetType: 'flow', InvocationTarget: 'Lookup_Account' })], {
        flowDefinitions: [{ Id: '300000000000002AAA', DeveloperName: 'Lookup_Account', ActiveVersionId: '301000000000002AAA' }],
        flows: [{ Id: '301000000000002AAA', Metadata: { actionCalls: [] } }],
      }),
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('makes no claim when flow metadata cannot be read', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([fn({ InvocationTargetType: 'flow', InvocationTarget: '300000000000003AAA' })], { flowDefinitions: new Error('INSUFFICIENT_ACCESS') }),
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('reports MEDIUM unverified for standard outbound actions named on a live topic with no definition row', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([], { pluginActions: [{ PluginId: '179T2', Function: 'Slack__SendMessageAsAgent' }, { PluginId: '179T2', Function: 'EmployeeCopilot__QueryRecords' }] }),
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-outbound-actions-unverified']);
    expect(findings[0].riskLevel).toBe('MEDIUM');
  });

  it('resolves topic action links that hold an action Id rather than a name', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok', agentInventory: [agent()],
      tables: live([fn({ Id: '172Z', PluginId: null, Source: 'Slack__ReplyInThread', InvocationTargetType: 'slack' })], { pluginActions: [{ PluginId: '179T2', Function: '172Z' }] }),
    });
    expect((await check.run(ctx)).findings.map((f) => f.id)).toEqual(['agent-outbound-actions-unconfirmed']);
  });

  it('degrades silently when the planner object is missing', async () => {
    const err = Object.assign(new Error('INVALID_TYPE'), { errorCode: 'INVALID_TYPE', statusCode: 400 });
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent()], tables: { planners: err } });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });
});
