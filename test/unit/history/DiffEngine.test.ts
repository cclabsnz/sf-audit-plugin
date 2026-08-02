// test/unit/history/DiffEngine.test.ts
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '@cclabsnz/sf-core';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    instanceUrl: 'https://test.salesforce.com',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const BASELINE = makeResult({
  healthScore: 64,
  grade: 'D',
  findings: [
    { id: 'f-resolved', checkId: 'c1', category: 'Auth', riskLevel: 'HIGH',     title: 'Old finding',       detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'CRITICAL', title: 'Severity changes',  detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',   title: 'Detail changes',    detail: 'old detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',      title: 'Unchanged finding', detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 5, codeCoveragePercent: 60, totalActiveUsers: 100 },
});

const CURRENT = makeResult({
  healthScore: 81,
  grade: 'B',
  findings: [
    { id: 'f-new',      checkId: 'c5', category: 'Auth', riskLevel: 'CRITICAL', title: 'New finding',       detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'HIGH',     title: 'Severity changes',  detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',   title: 'Detail changes',    detail: 'new detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',      title: 'Unchanged finding', detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 3, codeCoveragePercent: 75, totalActiveUsers: 100 },
});

describe('computeDiff', () => {
  const diff = computeDiff(BASELINE, CURRENT);

  it('attaches baseline and current', () => {
    expect(diff.baseline).toBe(BASELINE);
    expect(diff.current).toBe(CURRENT);
  });

  it('computes scoreDelta', () => {
    expect(diff.scoreDelta).toBe(17); // 81 - 64
  });

  it('computes gradeDelta', () => {
    expect(diff.gradeDelta).toBe('D → B');
  });

  it('gradeDelta is "unchanged" when grades are equal', () => {
    const sameGrade = computeDiff(BASELINE, makeResult({ grade: 'D', healthScore: 65 }));
    expect(sameGrade.gradeDelta).toBe('unchanged');
  });

  describe('findingChanges', () => {
    it('classifies new finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-new');
      expect(change?.type).toBe('new');
      expect(change?.previous).toBeUndefined();
    });

    it('classifies resolved finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-resolved');
      expect(change?.type).toBe('resolved');
    });

    it('classifies severity-changed finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-severity');
      expect(change?.type).toBe('severity-changed');
      expect(change?.previous?.riskLevel).toBe('CRITICAL');
      expect(change?.finding.riskLevel).toBe('HIGH');
    });

    it('classifies detail-changed finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-detail');
      expect(change?.type).toBe('detail-changed');
      expect(change?.previous?.detail).toBe('old detail');
      expect(change?.finding.detail).toBe('new detail');
    });

    it('classifies unchanged finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-unchanged');
      expect(change?.type).toBe('unchanged');
    });
  });

  describe('metricDeltas', () => {
    it('only includes metrics where before !== after', () => {
      // totalActiveUsers is 100 in both — should be absent
      expect(diff.metricDeltas.find((d) => d.key === 'totalActiveUsers')).toBeUndefined();
    });

    it('marks modifyAllDataUsersCount decrease as improved', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'modifyAllDataUsersCount')!;
      expect(delta.before).toBe(5);
      expect(delta.after).toBe(3);
      expect(delta.delta).toBe(-2);
      expect(delta.direction).toBe('improved');
    });

    it('marks codeCoveragePercent increase as improved', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'codeCoveragePercent')!;
      expect(delta.before).toBe(60);
      expect(delta.after).toBe(75);
      expect(delta.delta).toBe(15);
      expect(delta.direction).toBe('improved');
    });

    it('marks insecureRemoteSitesCount increase as degraded', () => {
      const withInsecure = computeDiff(
        makeResult({ metrics: { ...EMPTY_METRICS, insecureRemoteSitesCount: 0 } }),
        makeResult({ metrics: { ...EMPTY_METRICS, insecureRemoteSitesCount: 2 } }),
      );
      const delta = withInsecure.metricDeltas.find((d) => d.key === 'insecureRemoteSitesCount')!;
      expect(delta.direction).toBe('degraded');
    });

    it('includes human-readable label', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'modifyAllDataUsersCount')!;
      expect(delta.label).toBe('Modify All Data Users');
    });
  });
});
