import { jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AuditContext } from '@cclabsnz/sf-core';
import { AgentInventoryCheck } from '../../../../src/checks/impl/AgentInventoryCheck.js';
import { AgentQueryReachCheck } from '../../../../src/checks/impl/AgentQueryReachCheck.js';
import { AgentOutboundActionsCheck } from '../../../../src/checks/impl/AgentOutboundActionsCheck.js';
import { ChainEngine } from '../../../../src/chains/ChainEngine.js';
import type { Finding } from '../../../../src/findings/Finding.js';

// Replays rows captured read-only from a real org with one active Agentforce Employee Agent
// (General CRM topic, and a Flow action whose flow sends email with confirmation off). The
// Tooling and SOQL mocks answer exactly as that org did, including Tooling's INVALID_TYPE for
// the Bot objects. If a platform shape assumption is wrong, this is the test that fails.
const live = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../fixtures/agentforce/live-agent-v67.json', import.meta.url)), 'utf8'),
);

const invalidType = () => Promise.reject(Object.assign(new Error('sObject type is not supported.'), { errorCode: 'INVALID_TYPE', statusCode: 400 }));

function makeCtx(): AuditContext {
  const idOrName = (rows: any[], soql: string) => {
    const id = /Id = '([^']+)'/.exec(soql)?.[1];
    const name = /DeveloperName = '([^']+)'/.exec(soql)?.[1];
    return Promise.resolve(rows.filter((r) => (id ? r.Id === id : r.DeveloperName === name)));
  };
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((soql: string) => {
        if (/FROM BotDefinition/i.test(soql)) return Promise.resolve(live.botsSoql);
        if (/FROM BotVersion/i.test(soql)) return Promise.resolve(live.botVersionsSoql.filter((v: any) => v.Status === 'Active'));
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) => {
        if (/FROM Bot(Definition|Version)\b/i.test(soql)) return invalidType();
        if (/FROM GenAiPlannerFunctionDef/i.test(soql)) return Promise.resolve(live.plannerTopics);
        if (/FROM GenAiPlannerDefinition/i.test(soql)) return Promise.resolve(live.planners);
        if (/FROM GenAiPluginFunctionDef/i.test(soql)) return Promise.resolve(live.pluginActions);
        if (/FROM GenAiPluginDefinition/i.test(soql)) return Promise.resolve(live.plugins);
        if (/FROM GenAiFunctionDefinition/i.test(soql)) return Promise.resolve(live.functions);
        if (/FROM FlowDefinition/i.test(soql)) return idOrName(live.flowdef, soql);
        if (/FROM Flow\b/i.test(soql)) return idOrName(live.flowVersions, soql);
        return Promise.resolve([]);
      }),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'org1', name: 'Live', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://example.my.salesforce.com' },
    cache: {},
  } as any;
}

describe('AI & Agents checks against a captured live agent', () => {
  it('inventories the active agent even though Tooling rejects the Bot objects', async () => {
    const ctx = makeCtx();
    await new AgentInventoryCheck().run(ctx);
    expect(ctx.cache.agentAccess).toBe('ok');
    expect(ctx.cache.agentInventory).toEqual([
      expect.objectContaining({ developerName: 'CRM_Agent', type: 'agent', isActive: true, activeVersion: 2 }),
    ]);
  });

  it('finds open-ended query reach on the active version only, and the email-sending Flow action, and links them', async () => {
    const ctx = makeCtx();
    const findings: Finding[] = [];
    for (const check of [new AgentInventoryCheck(), new AgentQueryReachCheck(), new AgentOutboundActionsCheck()]) {
      findings.push(...(await check.run(ctx)).findings.map((f) => ({ ...f, checkId: check.id })));
    }

    const reach = findings.filter((f) => f.id.startsWith('agent-query-reach-'));
    expect(reach.map((f) => f.id)).toEqual(['agent-query-reach-CRM_Agent_v2']);
    expect(reach[0].detail).toContain('General CRM topic');
    expect(reach[0].detail).toContain('Query Records action (topic General CRM)');

    const outbound = findings.find((f) => f.id === 'agent-outbound-actions-unconfirmed');
    expect(outbound?.affectedItems).toEqual([
      expect.objectContaining({ label: 'Notify Lead By Email', note: 'email (flow Send_Lead_Email), no confirmation required' }),
    ]);

    const chains = new ChainEngine().correlate(findings);
    expect(chains.map((c) => c.id)).toContain('salesbleed-pattern');
  });
});
