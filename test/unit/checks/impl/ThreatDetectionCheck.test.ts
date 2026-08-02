import { jest } from '@jest/globals';
import { ThreatDetectionCheck } from '../../../../src/checks/impl/ThreatDetectionCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(queryAll: any): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('ThreatDetectionCheck', () => {
  const check = new ThreatDetectionCheck();

  it('flags MEDIUM when no anomaly store is queryable', async () => {
    const queryAll = jest.fn() as any;
    queryAll.mockRejectedValue(new Error('sObject not supported'));
    const r = await check.run(makeCtx(queryAll));
    const f = r.findings.find((x) => x.id === 'threat-detection-unavailable');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('flags MEDIUM when stores are present but empty', async () => {
    const queryAll = jest.fn() as any;
    queryAll.mockResolvedValue([]); // every store queryable, none has rows
    const r = await check.run(makeCtx(queryAll));
    expect(r.findings.some((f) => f.id === 'threat-detection-inactive' && f.riskLevel === 'MEDIUM')).toBe(true);
  });

  it('passes when the Guest User Anomaly store has recent events', async () => {
    const queryAll = jest.fn() as any;
    queryAll.mockResolvedValueOnce([{ EventDate: '2026-06-01T00:00:00Z' }]).mockResolvedValue([]);
    const r = await check.run(makeCtx(queryAll));
    expect(r.findings.some((f) => f.id === 'threat-detection-active' && f.passed)).toBe(true);
  });
});
