import { jest } from '@jest/globals';
import { AgentActionSurfaceCheck } from '../../../../src/checks/impl/AgentActionSurfaceCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';
import type { AgentDefinition } from '../../../../src/context/AuditCache.js';

type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: {
  agentInventory?: AgentDefinition[];
  agentAccess?: 'ok' | 'not-enabled' | 'unknown';
  tooling?: Handler;
}): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation(() => Promise.resolve([])),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) =>
        opts.tooling ? opts.tooling(soql) : Promise.resolve([]),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: {
      agentInventory: opts.agentInventory,
      agentAccess: opts.agentAccess,
    },
  } as any;
}

function apiError(errorCode: string, statusCode = 400): Error {
  return Object.assign(new Error(errorCode), { errorCode, statusCode });
}

function agent(overrides: Partial<AgentDefinition>): AgentDefinition {
  return {
    developerName: 'SalesAgent',
    label: 'Sales Agent',
    type: 'agent',
    isActive: true,
    activeVersion: 1,
    ...overrides,
  };
}

describe('AgentActionSurfaceCheck', () => {
  const check = new AgentActionSurfaceCheck();

  it('declares its cache contract', () => {
    expect(check.id).toBe('agent-action-surface');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['agentInventory', 'agentAccess']),
    );
  });

  it('is silent when agentAccess is not ok (not-enabled)', async () => {
    const ctx = makeCtx({
      agentAccess: 'not-enabled',
      agentInventory: [agent({})],
      tooling: () => Promise.reject(new Error('should not be queried')),
    });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('is silent when agentAccess is unknown', async () => {
    const ctx = makeCtx({ agentAccess: 'unknown', agentInventory: [agent({})] });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('flags HIGH for a write-capable Apex action and INFO for >15 actions', async () => {
    // 16 functions on one agent; one is a write-capable Apex invocation.
    const functions = Array.from({ length: 16 }, (_, i) => ({
      Id: `F${i}`,
      DeveloperName: `Action${i}`,
      MasterLabel: `Action ${i}`,
      InvocationTarget: i === 0 ? 'MyApexAction' : 'ReadSomething',
      InvocationTargetType: i === 0 ? 'apex' : 'flow',
    }));

    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ developerName: 'SalesAgent', label: 'Sales Agent' })],
      tooling: (soql) => {
        if (/GenAiPlugin/i.test(soql)) {
          return Promise.resolve([
            { Id: 'P1', DeveloperName: 'SalesTopic', MasterLabel: 'Sales Topic' },
          ]);
        }
        if (/GenAiFunction/i.test(soql)) {
          return Promise.resolve(functions);
        }
        return Promise.resolve([]);
      },
    });

    const result = await check.run(ctx);

    const high = result.findings.filter((f) => f.riskLevel === 'HIGH');
    expect(high.length).toBeGreaterThanOrEqual(1);
    expect(high.some((f) => f.id.startsWith('agent-action-surface-write'))).toBe(true);
    // Apex and Flow are both treated as write-capable (ambiguous invocation types).
    const writeFinding = high.find((f) => f.id.startsWith('agent-action-surface-write'));
    expect(writeFinding!.detail.toLowerCase()).toMatch(/apex|flow/);

    const info = result.findings.filter((f) => f.riskLevel === 'INFO' && f.id.startsWith('agent-action-surface-count'));
    expect(info).toHaveLength(1);
    expect(info[0].detail).toContain('16');
  });

  it('does not flag the action-count INFO at 15 actions (at threshold, not over)', async () => {
    const functions = Array.from({ length: 15 }, (_, i) => ({
      Id: `F${i}`,
      DeveloperName: `Action${i}`,
      MasterLabel: `Action ${i}`,
      InvocationTarget: 'ReadSomething',
      InvocationTargetType: 'reference',
    }));
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({})],
      tooling: (soql) => {
        if (/GenAiFunction/i.test(soql)) return Promise.resolve(functions);
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const info = result.findings.filter((f) => f.id.startsWith('agent-action-surface-count'));
    expect(info).toHaveLength(0);
  });

  it('degrades silently (no findings, no throw) when Tooling raises INVALID_TYPE for GenAI objects', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({})],
      tooling: () => Promise.reject(apiError('INVALID_TYPE', 400)),
    });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('falls back to the *Definition tooling object when the base object is INVALID_TYPE', async () => {
    // GenAiFunction is INVALID_TYPE but GenAiFunctionDefinition resolves.
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({})],
      tooling: (soql) => {
        if (/FROM GenAiFunctionDefinition/i.test(soql)) {
          return Promise.resolve([
            { Id: 'F1', DeveloperName: 'Writer', MasterLabel: 'Writer', InvocationTarget: 'ApexThing', InvocationTargetType: 'apex' },
          ]);
        }
        if (/FROM GenAiFunction\b/i.test(soql)) {
          return Promise.reject(apiError('INVALID_TYPE', 400));
        }
        if (/GenAiPlugin/i.test(soql)) {
          return Promise.reject(apiError('INVALID_TYPE', 400));
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const high = result.findings.filter((f) => f.riskLevel === 'HIGH');
    expect(high.some((f) => f.id.startsWith('agent-action-surface-write'))).toBe(true);
  });

  it('is silent when there are no active agents', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ isActive: false }), agent({ type: 'classic-bot', developerName: 'FaqBot' })],
      tooling: (soql) => {
        if (/GenAiFunction/i.test(soql)) {
          return Promise.resolve([
            { Id: 'F1', DeveloperName: 'Writer', MasterLabel: 'Writer', InvocationTarget: 'ApexThing', InvocationTargetType: 'apex' },
          ]);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    // No active agents to correlate against, so no findings even though write-capable actions exist.
    expect(result.findings).toHaveLength(0);
  });
});
