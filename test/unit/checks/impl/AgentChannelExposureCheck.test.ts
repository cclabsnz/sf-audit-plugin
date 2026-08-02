import { jest } from '@jest/globals';
import { AgentChannelExposureCheck } from '../../../../src/checks/impl/AgentChannelExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AgentDefinition, AgentAccess } from '@cclabsnz/sf-core';

// Route each SOQL/Tooling query by the sObject it hits so a fixture can supply
// per-object records (or per-object errors) without depending on call order.
type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: {
  soql?: Handler;
  tooling?: Handler;
  agentInventory?: AgentDefinition[];
  agentAccess?: AgentAccess;
}): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((soql: string) =>
        opts.soql ? opts.soql(soql) : Promise.resolve([]),
      ),
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

const agent = (over: Partial<AgentDefinition> = {}): AgentDefinition => ({
  developerName: 'SalesAgent',
  label: 'Sales Agent',
  type: 'agent',
  isActive: true,
  activeVersion: 1,
  runAsUserId: 'U1',
  runAsUserActive: true,
  ...over,
});

describe('AgentChannelExposureCheck', () => {
  const check = new AgentChannelExposureCheck();

  it('declares its cache contract', () => {
    expect(check.id).toBe('agent-channel-exposure');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['agentInventory', 'agentAccess']),
    );
  });

  it('is silent when agentAccess is not-enabled', async () => {
    const ctx = makeCtx({ agentAccess: 'not-enabled', agentInventory: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(0);
  });

  it('is silent when agentAccess is unknown', async () => {
    const ctx = makeCtx({ agentAccess: 'unknown', agentInventory: [agent()] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(0);
  });

  it('is silent when there are no active agents', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ isActive: false })],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(0);
  });

  // Fixture: agent explicitly bound (by BotUserId) to a guest-reachable Experience site.
  it('emits a critical finding for an agent on a guest-reachable Experience Cloud site', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ developerName: 'SalesAgent', label: 'Sales Agent', runAsUserId: 'U1' })],
      soql: (soql) => {
        if (/FROM Network/i.test(soql)) {
          return Promise.resolve([
            { Id: 'N1', Name: 'Help Center', Status: 'Live', UrlPathPrefix: 'help', GuestUserId: '005G' },
          ]);
        }
        if (/FROM MessagingChannel/i.test(soql)) {
          return Promise.resolve([]);
        }
        // EmbeddedServiceDetail rows tie a deployment to a Network (site) and a bot.
        if (/FROM EmbeddedService/i.test(soql)) {
          return Promise.resolve([
            { Id: 'ES1', DeveloperName: 'HelpChat', DurableId: 'ES1', Site: 'help', SiteName: 'Help Center' },
          ]);
        }
        return Promise.resolve([]);
      },
      tooling: (soql) => {
        // BotDefinition -> Network binding lookup: the agent is deployed on the guest site.
        if (/FROM EmbeddedServiceConfig|EmbeddedServiceDeployment/i.test(soql)) {
          return Promise.resolve([
            { Id: 'D1', DeveloperName: 'HelpChat', Site: 'N1', AgentDeveloperName: 'SalesAgent' },
          ]);
        }
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    const crit = r.findings.filter((f) => f.riskLevel === 'CRITICAL');
    // Either a precise mapped-exposure critical, OR the honest medium unmapped path.
    // This fixture provides an explicit agent->site binding, so it must be critical.
    expect(crit.length).toBeGreaterThanOrEqual(1);
    expect(crit[0].title).toMatch(/Sales Agent/);
    expect(JSON.stringify(crit[0])).toMatch(/Help Center/);
  });

  // Fixture: agent + only internal channels (no guest sites, no public deployments).
  it('emits an info finding for an agent on internal-only channels', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      soql: (soql) => {
        if (/FROM Network/i.test(soql)) return Promise.resolve([]); // no live guest sites
        if (/FROM MessagingChannel/i.test(soql)) {
          return Promise.resolve([
            { Id: 'MC1', MasterLabel: 'Internal SMS', ChannelType: 'Text', IsActive: true },
          ]);
        }
        if (/FROM EmbeddedService/i.test(soql)) return Promise.resolve([]);
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.riskLevel === 'CRITICAL')).toBe(false);
    const info = r.findings.filter((f) => f.riskLevel === 'INFO');
    expect(info.length).toBeGreaterThanOrEqual(1);
  });

  // Fixture: active agents AND discovered public channels, but no resolvable binding
  // between them -> honest medium "unmapped exposure" finding.
  it('emits a medium honest-inference finding when agent-to-channel mapping is unresolvable', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent({ developerName: 'SalesAgent', label: 'Sales Agent' })],
      soql: (soql) => {
        if (/FROM Network/i.test(soql)) {
          return Promise.resolve([
            { Id: 'N1', Name: 'Public Portal', Status: 'Live', UrlPathPrefix: 'portal', GuestUserId: '005G' },
          ]);
        }
        if (/FROM MessagingChannel/i.test(soql)) return Promise.resolve([]);
        // Public embedded deployment exists but carries no agent binding we can read.
        if (/FROM EmbeddedService/i.test(soql)) {
          return Promise.resolve([
            { Id: 'ES1', DeveloperName: 'AnonChat', DurableId: 'ES1', Site: null, SiteName: null },
          ]);
        }
        return Promise.resolve([]);
      },
      tooling: () => Promise.resolve([]), // no binding rows
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.riskLevel === 'CRITICAL')).toBe(false);
    const medium = r.findings.filter((f) => f.riskLevel === 'MEDIUM');
    expect(medium).toHaveLength(1);
    // Must be honest about inference vs fact.
    expect(medium[0].detail.toLowerCase()).toMatch(/manual|confirm|could not|cannot|inferred/);
    // Must list agents and channels separately.
    expect(JSON.stringify(medium[0])).toMatch(/Sales Agent/);
    expect(JSON.stringify(medium[0])).toMatch(/Public Portal/);
  });

  it('does not throw when channel objects are unavailable', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      soql: () => Promise.reject(new Error("sObject type 'Network' is not supported.")),
      tooling: () => Promise.reject(new Error('INVALID_TYPE')),
    });
    const r = await check.run(ctx);
    // No public channel could be discovered -> should not assert exposure.
    expect(r.findings.some((f) => f.riskLevel === 'CRITICAL')).toBe(false);
  });
});
