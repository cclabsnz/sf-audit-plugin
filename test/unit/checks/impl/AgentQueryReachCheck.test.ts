import { jest } from '@jest/globals';
import { AgentQueryReachCheck } from '../../../../src/checks/impl/AgentQueryReachCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AgentDefinition } from '@cclabsnz/sf-core';

type Tables = Partial<Record<
  'planners' | 'plannerTopics' | 'plugins' | 'pluginActions' | 'functions',
  unknown[] | Error
>>;

// Routes each Tooling query to a table by the object in its FROM clause.
function makeCtx(opts: {
  agentInventory?: AgentDefinition[];
  agentAccess?: 'ok' | 'not-enabled' | 'unknown';
  tables?: Tables;
}): AuditContext {
  const t = opts.tables ?? {};
  const pick = (v: unknown[] | Error | undefined) =>
    v instanceof Error ? Promise.reject(v) : Promise.resolve(v ?? []);
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) => {
        if (/FROM GenAiPlannerFunctionDef/i.test(soql)) return pick(t.plannerTopics);
        if (/FROM GenAiPlannerDefinition/i.test(soql)) return pick(t.planners);
        if (/FROM GenAiPluginFunctionDef/i.test(soql)) return pick(t.pluginActions);
        if (/FROM GenAiPluginDefinition/i.test(soql)) return pick(t.plugins);
        if (/FROM GenAiFunctionDefinition/i.test(soql)) return pick(t.functions);
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

const planner = { Id: '16jP1', DeveloperName: 'SalesAgent', MasterLabel: 'Sales Agent' };

describe('AgentQueryReachCheck', () => {
  const check = new AgentQueryReachCheck();

  it('declares its identity and cache contract', () => {
    expect(check.id).toBe('agent-query-reach');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['agentInventory', 'agentAccess']));
  });

  it('is silent when agentAccess is not ok', async () => {
    const ctx = makeCtx({ agentAccess: 'unknown', agentInventory: [agent()] });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('is silent when there are no active agents', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ isActive: false })],
      tables: { planners: [planner], plannerTopics: [{ PlannerId: '16jP1', Plugin: 'EmployeeCopilot__GeneralCRM' }] },
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('flags HIGH when a planner has the standard General CRM topic', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: { planners: [planner], plannerTopics: [{ PlannerId: '16jP1', Plugin: 'EmployeeCopilot__GeneralCRM' }] },
    });
    const { findings } = await check.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('agent-query-reach-SalesAgent');
    expect(findings[0].riskLevel).toBe('HIGH');
    expect(findings[0].title).toContain('Sales Agent');
    expect(findings[0].detail).toContain('General CRM');
  });

  it('flags a local topic whose Source is General CRM', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: {
        planners: [planner],
        plugins: [{ Id: '179L1', DeveloperName: 'GeneralCRM_16jP1', MasterLabel: 'General CRM', Source: 'EmployeeCopilot__GeneralCRM', PlannerId: '16jP1' }],
      },
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-query-reach-SalesAgent']);
  });

  it('flags a Query Records action reached through a custom topic on the planner', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: {
        planners: [planner],
        plannerTopics: [{ PlannerId: '16jP1', Plugin: 'LeadTriage' }],
        plugins: [{ Id: '179C1', DeveloperName: 'LeadTriage', MasterLabel: 'Lead Triage', Source: null, PlannerId: null }],
        pluginActions: [{ PluginId: '179C1', Function: 'EmployeeCopilot__QueryRecords' }],
      },
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-query-reach-SalesAgent']);
    expect(findings[0].detail).toContain('Query Records');
  });

  it('flags a local Query Records function tied to the planner', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: {
        planners: [planner],
        functions: [{ Id: '17bF1', DeveloperName: 'QueryRecords_16jP1', MasterLabel: 'Query Records', Source: 'EmployeeCopilot__QueryRecordsWithAggregate', PlannerId: '16jP1', PluginId: null }],
      },
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-query-reach-SalesAgent']);
  });

  it('does not flag a planner with only narrow actions', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: {
        planners: [planner],
        plannerTopics: [{ PlannerId: '16jP1', Plugin: 'LeadTriage' }],
        plugins: [{ Id: '179C1', DeveloperName: 'LeadTriage', MasterLabel: 'Lead Triage', Source: null, PlannerId: null }],
        pluginActions: [{ PluginId: '179C1', Function: 'EmployeeCopilot__SummarizeRecord' }],
      },
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('reports MEDIUM unmapped when Query Records exists but no planner link resolves', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: {
        planners: [planner],
        plugins: [{ Id: '179X', DeveloperName: 'Orphan', MasterLabel: 'Orphan', Source: null, PlannerId: null }],
        pluginActions: [{ PluginId: '179X', Function: 'EmployeeCopilot__QueryRecords' }],
      },
    });
    const { findings } = await check.run(ctx);
    expect(findings.map((f) => f.id)).toEqual(['agent-query-reach-unmapped']);
    expect(findings[0].riskLevel).toBe('MEDIUM');
  });

  it('degrades silently when the planner object is missing', async () => {
    const err = Object.assign(new Error('INVALID_TYPE'), { errorCode: 'INVALID_TYPE', statusCode: 400 });
    const ctx = makeCtx({ agentAccess: 'ok', agentInventory: [agent()], tables: { planners: err } });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  it('still evaluates when an optional link table fails', async () => {
    const err = Object.assign(new Error('INVALID_TYPE'), { errorCode: 'INVALID_TYPE', statusCode: 400 });
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      tables: { planners: [planner], plannerTopics: [{ PlannerId: '16jP1', Plugin: 'EmployeeCopilot__GeneralCRM' }], functions: err, pluginActions: err },
    });
    expect((await check.run(ctx)).findings.map((f) => f.id)).toEqual(['agent-query-reach-SalesAgent']);
  });
});
