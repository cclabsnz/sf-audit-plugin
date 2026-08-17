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

  // Fixture: agent + a messaging channel, but no guest sites and no public deployments.
  // Note this is "no public binding confirmed", NOT "internal-only": MessagingChannel also
  // covers Messaging for In-App and Web, which is a public web surface, and nothing here ties
  // an agent to a channel either way.
  it('emits an info finding when no public channel binding could be confirmed', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      soql: (soql) => {
        if (/FROM Network/i.test(soql)) return Promise.resolve([]); // no live guest sites
        if (/FROM MessagingChannel/i.test(soql)) {
          return Promise.resolve([
            { Id: 'MC1', MasterLabel: 'Support SMS', MessageType: 'Text', PlatformType: 'Enhanced', IsActive: true },
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

    // The channel count must not be dressed up as internal or authenticated reach. Creating a
    // "Messaging for In-App and Web" channel also creates a MessagingChannel record, and that one
    // is publicly reachable via the messaging API's unauthenticated guest token flow — so a
    // blanket "internal / authenticated inbound surfaces" claim would under-report real exposure.
    // The title must not assert internal-only reach...
    expect(info[0].title).not.toMatch(/internal[- ]only/i);
    // ...and the channel count must not be labelled internal or authenticated.
    expect(info[0].detail).not.toMatch(/internal \/ authenticated/i);
    // "internal-only" may appear in the detail, but only as the thing being ruled out.
    for (const m of info[0].detail.matchAll(/internal[- ]only/gi)) {
      const preceding = info[0].detail.slice(Math.max(0, m.index - 60), m.index);
      expect(preceding).toMatch(/\bnot\b/i);
    }
    // A non-web channel (Text) is described accurately: external senders, not authenticated,
    // but not a browser endpoint, and no exposure asserted because no binding exists.
    expect(info[0].detail).toMatch(/non-web messaging channel/i);
    expect(info[0].detail).toMatch(/Text/);
    expect(info[0].detail).toMatch(/not\s+Salesforce-authenticated/i);
    expect(info[0].detail).toMatch(/no queryable binding/i);
  });

  // Regression: the field is MessageType. Selecting a non-existent ChannelType raised
  // INVALID_FIELD, which the surrounding catch swallowed — so every messaging channel silently
  // vanished and the check could never see a web-type channel at all.
  it('queries MessageType, never ChannelType', async () => {
    const queries: string[] = [];
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      soql: (soql) => {
        queries.push(soql);
        return Promise.resolve([]);
      },
    });
    await check.run(ctx);
    const channelQuery = queries.find((q) => /FROM MessagingChannel/i.test(q));
    expect(channelQuery).toBeDefined();
    expect(channelQuery).toMatch(/MessageType/);
    expect(channelQuery).not.toMatch(/ChannelType/);
  });

  // A web-type messaging channel is a browser-reachable surface, so it must be treated as a
  // public channel candidate rather than counted as a benign internal one.
  it.each(['EmbeddedMessaging', 'WebChat'])(
    'treats a %s messaging channel as a public channel candidate',
    async (messageType) => {
      const ctx = makeCtx({
        agentAccess: 'ok',
        agentInventory: [agent()],
        soql: (soql) => {
          if (/FROM MessagingChannel/i.test(soql)) {
            return Promise.resolve([
              { Id: 'MC9', MasterLabel: 'Web Support', MessageType: messageType, PlatformType: 'Enhanced', IsActive: true },
            ]);
          }
          return Promise.resolve([]);
        },
      });
      const r = await check.run(ctx);
      // No binding exists, so this is the honest MEDIUM "mapping unconfirmed" finding...
      const medium = r.findings.filter((f) => f.riskLevel === 'MEDIUM');
      expect(medium).toHaveLength(1);
      expect(JSON.stringify(medium[0])).toMatch(/Web Support/);
      // ...and it must NOT be reported as having no public channel.
      expect(r.findings.some((f) => f.id === 'agent-channel-exposure-internal')).toBe(false);
    },
  );

  it('does not treat an inactive web channel as public', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      soql: (soql) => {
        if (/FROM MessagingChannel/i.test(soql)) {
          return Promise.resolve([
            { Id: 'MC9', MasterLabel: 'Old Web', MessageType: 'EmbeddedMessaging', IsActive: false },
          ]);
        }
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.riskLevel === 'MEDIUM')).toBe(false);
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
