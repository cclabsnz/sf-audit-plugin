import { jest } from '@jest/globals';
import { AgentMonitoringCoverageCheck } from '../../../../src/checks/impl/AgentMonitoringCoverageCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { AgentDefinition, AgentAccess, EventLogSummary } from '@cclabsnz/sf-core';

type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: {
  tooling?: Handler;
  agentInventory?: AgentDefinition[];
  agentAccess?: AgentAccess;
  eventLogSummary?: EventLogSummary;
}): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
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
      eventLogSummary: opts.eventLogSummary,
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

const captured: EventLogSummary = {
  earliestDate: '2026-06-20',
  totalFiles: 42,
  eventTypes: ['Login', 'ApiTotalUsage'],
  accessible: true,
};

const noCapture: EventLogSummary = {
  earliestDate: null,
  totalFiles: 0,
  eventTypes: [],
  accessible: true,
};

const blindEventLog: EventLogSummary = {
  earliestDate: null,
  totalFiles: 0,
  eventTypes: [],
  accessible: false,
  accessError: 'not-enabled',
};

describe('AgentMonitoringCoverageCheck', () => {
  const check = new AgentMonitoringCoverageCheck();

  it('declares its cache contract', () => {
    expect(check.id).toBe('agent-monitoring-coverage');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['agentInventory', 'agentAccess', 'eventLogSummary']),
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
      eventLogSummary: noCapture,
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(0);
  });

  // Active agents + no event capture + no transaction security policies -> HIGH.
  it('emits a high finding when agents exist but nothing is monitored', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: noCapture,
      tooling: (soql) => {
        if (/TransactionSecurityPolicy/i.test(soql)) return Promise.resolve([]);
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    const high = r.findings.filter((f) => f.riskLevel === 'HIGH');
    expect(high).toHaveLength(1);
    expect(high[0].remediation).toMatch(/sf audit events pull/);
  });

  // 'not-enabled' is assigned to INVALID_TYPE, which Salesforce also returns when the audit user
  // cannot see EventLogFile, so it is not evidence that nothing is captured.
  it('treats a not-enabled event log as unknown, not no capture', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: blindEventLog,
      tooling: () => Promise.resolve([]),
    });
    const r = await check.run(ctx);
    expect(r.findings.filter((f) => f.riskLevel === 'HIGH')).toHaveLength(0);
    expect(r.findings.map((f) => f.id)).toEqual(['agent-monitoring-coverage-unreadable']);
  });

  // A log the audit user cannot read is not evidence that nothing is captured.
  it.each([
    ['no permission to read the event log', { ...blindEventLog, accessError: 'no-permission' as const }],
    ['an unclassified event log failure', { ...blindEventLog, accessError: 'unknown' as const }],
    ['no event log summary at all', undefined],
  ])('is inconclusive, not high, with %s', async (_label, eventLogSummary) => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary,
      tooling: () => Promise.resolve([]),
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({
      id: 'agent-monitoring-coverage-unreadable',
      riskLevel: 'INFO',
      inconclusive: true,
    });
  });

  it('is inconclusive when the Transaction Security policies cannot be read', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: captured,
      tooling: () => Promise.reject(new Error('INSUFFICIENT_ACCESS_OR_READONLY')),
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['agent-monitoring-coverage-unreadable']);
    expect(r.findings[0].detail).toMatch(/Transaction Security policies/);
  });

  it('stays silent when a policy is enabled even if the event log is unreadable', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: { ...blindEventLog, accessError: 'no-permission' },
      tooling: () => Promise.resolve([{ Id: 'TSP1', State: 'Enabled' }]),
    });
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });

  // Partial: event logs exist but no transaction security policies -> LOW.
  it('emits a low finding when event logs exist but no transaction security policy does', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: captured,
      tooling: (soql) => {
        if (/TransactionSecurityPolicy/i.test(soql)) return Promise.resolve([]);
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    const low = r.findings.filter((f) => f.riskLevel === 'LOW');
    expect(low).toHaveLength(1);
    expect(r.findings.some((f) => f.riskLevel === 'HIGH')).toBe(false);
  });

  // Healthy: event logs + at least one transaction security policy -> silent.
  it('is silent when monitoring is healthy', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: captured,
      tooling: (soql) => {
        if (/TransactionSecurityPolicy/i.test(soql)) {
          return Promise.resolve([{ Id: 'P1', State: 'Enabled' }]);
        }
        return Promise.resolve([]);
      },
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(0);
  });

  // INVALID_TYPE on TransactionSecurityPolicy may mean the audit user cannot see it, so unknown.
  it('does not throw, and is inconclusive, when TransactionSecurityPolicy is unavailable', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentInventory: [agent()],
      eventLogSummary: noCapture,
      tooling: () => Promise.reject(new Error('INVALID_TYPE')),
    });
    const r = await check.run(ctx);
    // no capture + an unreadable policy -> inconclusive, never high
    expect(r.findings.filter((f) => f.riskLevel === 'HIGH')).toHaveLength(0);
    expect(r.findings.map((f) => f.id)).toEqual(['agent-monitoring-coverage-unreadable']);
  });
});
