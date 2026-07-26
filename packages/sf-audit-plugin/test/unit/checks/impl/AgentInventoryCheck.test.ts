import { jest } from '@jest/globals';
import { AgentInventoryCheck } from '../../../../src/checks/impl/AgentInventoryCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Route each query by the sObject it hits so a fixture can supply per-object records
// (or per-object errors) without depending on call order.
type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: { tooling: Handler; soql?: Handler }): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((soql: string) =>
        opts.soql ? opts.soql(soql) : Promise.resolve([]),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) => opts.tooling(soql)),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: {},
  } as any;
}

function apiError(errorCode: string, statusCode = 400): Error {
  return Object.assign(new Error(errorCode), { errorCode, statusCode });
}

describe('AgentInventoryCheck', () => {
  const check = new AgentInventoryCheck();

  it('declares its cache contract', () => {
    expect(check.id).toBe('agent-inventory');
    expect(check.category).toBe('AI & Agents');
    expect(check.populatesCache).toEqual(
      expect.arrayContaining(['agentInventory', 'agentUsers', 'agentAccess']),
    );
  });

  // Fixture (a): 2 agents + 1 classic bot + agent users, one active agent's run-as user frozen.
  it('inventories agents and bots and flags an active agent whose run-as user is frozen', async () => {
    const ctx = makeCtx({
      tooling: (soql) => {
        if (/FROM BotDefinition/i.test(soql)) {
          return Promise.resolve([
            { Id: 'B1', DeveloperName: 'SalesAgent', MasterLabel: 'Sales Agent', Type: 'EinsteinServiceAgent', BotUserId: 'U1' },
            { Id: 'B2', DeveloperName: 'SupportAgent', MasterLabel: 'Support Agent', Type: 'EinsteinServiceAgent', BotUserId: 'U2' },
            { Id: 'B3', DeveloperName: 'FaqBot', MasterLabel: 'FAQ Bot', Type: 'Bot', BotUserId: null },
          ]);
        }
        if (/FROM BotVersion/i.test(soql)) {
          return Promise.resolve([
            { Id: 'V1', BotDefinitionId: 'B1', Status: 'Active', VersionNumber: 3 },
            { Id: 'V2', BotDefinitionId: 'B2', Status: 'Active', VersionNumber: 1 },
            // B3 has no active version
          ]);
        }
        if (/FROM GenAiPlannerDefinition/i.test(soql)) {
          return Promise.resolve([{ Id: 'P1', DeveloperName: 'SalesAgent', MasterLabel: 'Sales Agent Planner' }]);
        }
        return Promise.resolve([]);
      },
      soql: (soql) => {
        if (/PermissionSetLicenseAssign/i.test(soql)) {
          return Promise.resolve([
            { AssigneeId: 'U1', PermissionSetLicense: { MasterLabel: 'Einstein Agent User' } },
          ]);
        }
        // run-as user status query — selects the collected run-as user ids
        if (/IsFrozen|FROM User WHERE Id IN/i.test(soql)) {
          return Promise.resolve([
            { Id: 'U1', IsActive: true },
            { Id: 'U2', IsActive: false },
          ]);
        }
        // agent-user population query
        return Promise.resolve([
          {
            Id: 'U1', Username: 'agent.runner@x.com', IsActive: true,
            Profile: { Name: 'Einstein Agent User' },
            PermissionSetAssignments: { records: [{ PermissionSetId: 'PS1' }] },
          },
          {
            Id: 'U2', Username: 'frozen.agent@x.com', IsActive: false,
            Profile: { Name: 'Einstein Agent User' },
            PermissionSetAssignments: { records: [] },
          },
        ]);
      },
    });

    const result = await check.run(ctx);

    expect(ctx.cache.agentAccess).toBe('ok');
    expect(ctx.cache.agentInventory).toHaveLength(3);

    const agents = (ctx.cache.agentInventory ?? []).filter((a) => a.type === 'agent');
    const bots = (ctx.cache.agentInventory ?? []).filter((a) => a.type === 'classic-bot');
    expect(agents).toHaveLength(2);
    expect(bots).toHaveLength(1);

    const sales = (ctx.cache.agentInventory ?? []).find((a) => a.developerName === 'SalesAgent');
    expect(sales?.isActive).toBe(true);
    expect(sales?.activeVersion).toBe(3);
    expect(sales?.runAsUserId).toBe('U1');
    expect(sales?.runAsUserActive).toBe(true);

    const support = (ctx.cache.agentInventory ?? []).find((a) => a.developerName === 'SupportAgent');
    expect(support?.isActive).toBe(true);
    expect(support?.runAsUserActive).toBe(false);

    const faq = (ctx.cache.agentInventory ?? []).find((a) => a.developerName === 'FaqBot');
    expect(faq?.isActive).toBe(false);

    // agent users cache
    expect((ctx.cache.agentUsers ?? []).map((u) => u.userId).sort()).toEqual(['U1', 'U2']);
    const u1 = (ctx.cache.agentUsers ?? []).find((u) => u.userId === 'U1');
    expect(u1?.permissionSetIds).toContain('PS1');
    expect(u1?.permissionSetLicenseNames).toContain('Einstein Agent User');

    // one info summary finding
    const info = result.findings.find((f) => f.id === 'agent-inventory-summary');
    expect(info).toBeDefined();
    expect(info!.riskLevel).toBe('INFO');

    // one medium finding for the active agent whose run-as user is frozen/inactive
    const medium = result.findings.filter((f) => f.riskLevel === 'MEDIUM');
    expect(medium).toHaveLength(1);
    expect(medium[0].affectedItems?.[0].label).toContain('Support Agent');
  });

  // Fixture (b): no-Agentforce org — Tooling throws INVALID_TYPE.
  it('degrades to not-enabled with zero findings when GenAI/Bot objects do not exist', async () => {
    const ctx = makeCtx({
      tooling: async () => {
        throw apiError('INVALID_TYPE', 400);
      },
    });

    const result = await check.run(ctx);

    expect(ctx.cache.agentAccess).toBe('not-enabled');
    expect(ctx.cache.agentInventory).toEqual([]);
    expect(ctx.cache.agentUsers).toEqual([]);
    expect(result.findings).toHaveLength(0);
  });

  it('does not throw when a non-ApiError message says the sObject type is not supported', async () => {
    const ctx = makeCtx({
      tooling: async () => {
        throw new Error("sObject type 'BotDefinition' is not supported.");
      },
    });
    const result = await check.run(ctx);
    expect(ctx.cache.agentAccess).toBe('not-enabled');
    expect(result.findings).toHaveLength(0);
  });

  // Fixture (c): partial failure — BotDefinition works, GenAiPlannerDefinition errors.
  // Decision: BotDefinition succeeding proves the Bot/Agent objects exist, so this is NOT
  // 'not-enabled'. GenAiPlannerDefinition is supplementary (planner labels only). A failure
  // there means we could not fully build the inventory, so we degrade to 'unknown' and return
  // zero findings rather than assert an inventory we could not complete. Consumers keyed on
  // agentAccess === 'ok' will therefore stay silent, matching the EventLogSummary blind-spot
  // convention.
  it('degrades to unknown when BotDefinition works but GenAiPlannerDefinition errors', async () => {
    const ctx = makeCtx({
      tooling: (soql) => {
        if (/FROM BotDefinition/i.test(soql)) {
          return Promise.resolve([
            { Id: 'B1', DeveloperName: 'SalesAgent', MasterLabel: 'Sales Agent', Type: 'EinsteinServiceAgent', BotUserId: null },
          ]);
        }
        if (/FROM BotVersion/i.test(soql)) {
          return Promise.resolve([{ Id: 'V1', BotDefinitionId: 'B1', Status: 'Active', VersionNumber: 1 }]);
        }
        if (/FROM GenAiPlannerDefinition/i.test(soql)) {
          return Promise.reject(apiError('INSUFFICIENT_ACCESS', 403));
        }
        return Promise.resolve([]);
      },
    });

    const result = await check.run(ctx);
    expect(ctx.cache.agentAccess).toBe('unknown');
    expect(result.findings).toHaveLength(0);
  });
});
