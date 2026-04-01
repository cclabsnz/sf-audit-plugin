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
  return { id, checkId: 'test-check', category: 'Test', riskLevel, title: 'T', detail: 'd', remediation: 'r' };
}

describe('buildAuditResult', () => {
  it('returns healthScore=100 and grade=A for no findings', () => {
    const result = buildAuditResult(makeCtx(), [], {});
    expect(result.healthScore).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('returns grade=F when the sole finding is CRITICAL', () => {
    const result = buildAuditResult(makeCtx(), [finding('CRITICAL')], {});
    expect(result.grade).toBe('F');
  });

  it('returns grade=F when healthScore < 40', () => {
    const findings = Array.from({ length: 10 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('F');
    expect(result.healthScore).toBeLessThan(40);
  });

  it('returns grade=F when healthScore < 40 (4 HIGH findings)', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('F');
    expect(result.healthScore).toBe(30);
  });

  it('returns grade=D when healthScore is between 40 and 55 (2 HIGH + 1 LOW)', () => {
    const findings = [finding('HIGH', 'f1'), finding('HIGH', 'f2'), finding('LOW', 'f3')];
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('D');
    expect(result.healthScore).toBe(50);
  });

  it('returns grade=C when healthScore is between 55 and 70 with low high count (4 MEDIUM)', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('MEDIUM', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('C');
    expect(result.healthScore).toBe(60);
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

  describe('with custom ScoringConfig', () => {
    it('uses checkWeights override for matching checkId', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: { 'my-check': 10 },
        gradeThresholds: {
          A: { minScore: 85, maxHigh: 0 },
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      // A LOW finding from 'my-check' should score 10, not 1
      const f: Finding = { id: 'f1', checkId: 'my-check', category: 'Test', riskLevel: 'LOW', title: 'T', detail: 'd', remediation: 'r' };
      const result = buildAuditResult(makeCtx(), [f], {}, config);
      // totalScore=10, maxPossible=10 → healthScore=0
      expect(result.healthScore).toBe(0);
    });

    it('falls back to riskScores for checkIds not in checkWeights', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: {},
        gradeThresholds: {
          A: { minScore: 85, maxHigh: 0 },
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      const f: Finding = { id: 'f1', checkId: 'other-check', category: 'Test', riskLevel: 'INFO', title: 'T', detail: 'd', remediation: 'r' };
      const result = buildAuditResult(makeCtx(), [f], {}, config);
      expect(result.healthScore).toBe(100); // INFO=0, no penalty
    });

    it('falls back to riskScores when checkId is undefined', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: { 'my-check': 99 },
        gradeThresholds: {
          A: { minScore: 85, maxHigh: 0 },
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      // Finding with no checkId — should NOT use checkWeights, should use riskScores
      const f: Finding = { id: 'f1', category: 'Test', riskLevel: 'INFO', title: 'T', detail: 'd', remediation: 'r' };
      const result = buildAuditResult(makeCtx(), [f], {}, config);
      expect(result.healthScore).toBe(100); // INFO=0, not checkWeights[undefined]=99
    });

    it('applies config-driven grade thresholds', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: {},
        gradeThresholds: {
          A: { minScore: 95 }, // raised threshold
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      // Zero findings → healthScore=100, minScore=95 → should be A
      const result = buildAuditResult(makeCtx(), [], {}, config);
      expect(result.grade).toBe('A');
    });
  });
});
