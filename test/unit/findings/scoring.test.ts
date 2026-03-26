import { buildAuditResult } from '../../../src/findings/scoring.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AuditContext } from '../../../src/context/AuditContext.js';

function makeCtx(): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    queries: {} as any,
    orgInfo: { id: 'orgId', name: 'Test Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://test.salesforce.com' },
    cache: {},
  };
}

function finding(riskLevel: Finding['riskLevel'], id = 'f1'): Finding {
  return { id, category: 'Test', riskLevel, title: 'T', detail: 'd', remediation: 'r' };
}

describe('buildAuditResult', () => {
  it('returns healthScore=100 and grade=A for no findings', () => {
    const result = buildAuditResult(makeCtx(), [], {});
    expect(result.healthScore).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('returns grade=F when any CRITICAL finding exists', () => {
    const result = buildAuditResult(makeCtx(), [finding('CRITICAL')], {});
    expect(result.grade).toBe('F');
  });

  it('returns grade=F when healthScore < 40', () => {
    const findings = Array.from({ length: 10 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('F');
    expect(result.healthScore).toBeLessThan(40);
  });

  it('returns grade=D when highCount > 3', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('D');
  });

  it('returns grade=C when highCount > 1', () => {
    const findings = [finding('HIGH', 'f1'), finding('HIGH', 'f2'), finding('LOW', 'f3')];
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('C');
  });

  it('returns grade=B when mediumCount > 3', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('MEDIUM', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('B');
  });

  it('returns grade=A for only INFO findings', () => {
    const findings = Array.from({ length: 5 }, (_, i) => finding('INFO', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('A');
    expect(result.healthScore).toBe(100);
  });

  it('populates orgInfo fields from ctx.orgInfo', () => {
    const result = buildAuditResult(makeCtx(), [], {});
    expect(result.orgId).toBe('orgId');
    expect(result.orgName).toBe('Test Org');
    expect(result.isSandbox).toBe(false);
  });

  it('merges provided metrics with EMPTY_METRICS defaults', () => {
    const result = buildAuditResult(makeCtx(), [], { totalActiveUsers: 42 });
    expect(result.metrics.totalActiveUsers).toBe(42);
    expect(result.metrics.apexClassCount).toBe(0);
  });
});
