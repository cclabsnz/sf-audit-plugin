import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { buildSummary } from '../../../src/findings/summary.js';
import { buildDigest } from '../../../src/findings/digest.js';

const finding = (id: string, riskLevel: RiskLevel, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id.split('-')[0], category: 'Test', riskLevel,
  title: `${id} title`, detail: 'Long prose an agent pays for and rarely needs.', remediation: 'Do the thing.', ...extra,
});

const chain = (id: string, named: boolean, findingId: string): AttackChain => ({
  id, title: `${id} title`, severity: 'CRITICAL', confidence: named ? 'named' : 'potential', narrative: 'n', remediation: 'r',
  ...(named ? { abuseCase: { actor: 'a', goal: 'g', preconditions: [], breakPoint: `Fix ${findingId}` } as never } : {}),
  steps: [{ findingId, capability: 'data-read' as never, breaksChain: named ? true : undefined } as never],
});

const result = (findings: Finding[], chains: AttackChain[] = [], extra: Partial<AuditResult> = {}): AuditResult => ({
  generatedAt: new Date('2026-11-11T00:00:00Z'), orgId: '00D000000000001', orgName: 'Test Org', orgType: 'Production',
  isSandbox: false, instance: 'NA1', instanceUrl: 'https://example.my.salesforce.com', findings,
  metrics: {} as AuditResult['metrics'], healthScore: 61, grade: 'D', attackChains: chains, ...extra,
});

describe('buildSummary: page one of the report as data', () => {
  it('carries the grade, its reason and coverage, which the digest drops', () => {
    const s = buildSummary(result([finding('a-1', 'HIGH')], [], {
      gradeReason: 'D: 1 HIGH', coverage: { checksRun: 10, checksAssessed: 9, percent: 90, notAssessed: ['x'], capped: false } as never,
    }));
    expect(s.gradeReason).toBe('D: 1 HIGH');
    expect(s.coverage).toEqual({ percent: 90, checksAssessed: 9, checksRun: 10, notAssessed: ['x'] });
  });

  it('lists the fix-first plan with the finding ids each action closes, ranked and in waves', () => {
    const s = buildSummary(result([finding('a-1', 'CRITICAL'), finding('b-1', 'HIGH'), finding('c-1', 'LOW', { passed: true })]));
    expect(s.actions.map((a) => a.rank)).toEqual(s.actions.map((_, i) => i + 1));
    expect(s.actions.flatMap((a) => a.closes).sort()).toEqual(['a-1', 'b-1']);
    expect(s.actions[0].wave).toBe('Start now');
    expect(s.headline.length).toBeGreaterThan(0);
  });

  it('labels chains C1 for named and P1 for potential, as the reports do, and links actions to them', () => {
    const s = buildSummary(result([finding('a-1', 'CRITICAL'), finding('b-1', 'HIGH')], [chain('x', true, 'a-1'), chain('y', false, 'b-1')]));
    expect(s.attackChains.map((c) => [c.label, c.breakPoint])).toEqual([['C1', 'Fix a-1'], ['P1', undefined]]);
    expect(s.actions.find((a) => a.closes.includes('a-1'))!.breaks).toEqual(['C1']);
  });

  it('never carries detail prose or affected-item lists', () => {
    const affectedItems = Array.from({ length: 500 }, (_, i) => ({ label: `item ${i}` }));
    const findings = Array.from({ length: 60 }, (_, i) => finding(`k${i}-1`, i % 2 ? 'HIGH' : 'MEDIUM', { affectedItems }));
    const json = JSON.stringify(buildSummary(result(findings)));
    expect(json).not.toContain('Long prose');
    expect(json).not.toContain('item 4');
    // Far smaller than the digest of the same run.
    expect(json.length).toBeLessThan(JSON.stringify(buildDigest(result(findings))).length / 2);
  });
});
