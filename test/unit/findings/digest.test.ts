import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { buildDigest } from '../../../src/findings/digest.js';

const finding = (riskLevel: RiskLevel, extra: Partial<Finding> = {}): Finding => ({
  id: `${riskLevel}-${extra.checkId ?? 'x'}`,
  checkId: 'some-check',
  category: 'Test',
  riskLevel,
  title: `${riskLevel} finding`,
  detail: 'A long prose explanation that agents pay for and rarely need.',
  remediation: 'Do the thing.',
  ...extra,
});

const result = (findings: Finding[]): AuditResult => ({
  generatedAt: new Date('2026-09-07T00:00:00Z'),
  orgId: '00D000000000001',
  orgName: 'Test Org',
  orgType: 'Production',
  isSandbox: false,
  instance: 'APAC1',
  instanceUrl: 'https://example.my.salesforce.com',
  findings,
  metrics: { totalUsers: 240 } as unknown as AuditResult['metrics'],
  healthScore: 61,
  grade: 'D',
  attackChains: [],
});

describe('buildDigest', () => {
  it('drops passed findings from the finding list', () => {
    const d = buildDigest(result([finding('INFO', { passed: true }), finding('HIGH')]));
    expect(d.findings).toHaveLength(1);
    expect(d.findings[0].riskLevel).toBe('HIGH');
  });

  it('counts passed findings even though it drops them', () => {
    const d = buildDigest(result([finding('INFO', { passed: true }), finding('HIGH')]));
    expect(d.counts.passed).toBe(1);
    expect(d.counts.high).toBe(1);
  });

  it('drops the detail prose from active findings', () => {
    const d = buildDigest(result([finding('HIGH')]));
    expect(JSON.stringify(d)).not.toContain('agents pay for');
  });

  it('keeps remediation on active findings', () => {
    const d = buildDigest(result([finding('HIGH')]));
    expect(d.findings[0].remediation).toBe('Do the thing.');
  });

  it('replaces a long affectedItems list with a count and a capped sample', () => {
    const affectedItems = Array.from({ length: 40 }, (_, i) => ({ label: `user${i}` }));
    const d = buildDigest(result([finding('HIGH', { affectedItems })]));
    expect(d.findings[0].affectedCount).toBe(40);
    expect(d.findings[0].affectedSample).toEqual(['user0', 'user1', 'user2']);
  });

  it('omits the affected fields entirely when a finding has none', () => {
    const d = buildDigest(result([finding('HIGH')]));
    expect(d.findings[0].affectedCount).toBeUndefined();
    expect(d.findings[0].affectedSample).toBeUndefined();
  });

  it('reduces inconclusive findings to checkId and title, in their own list', () => {
    const d = buildDigest(result([finding('INFO', { inconclusive: true, checkId: 'code-security' })]));
    expect(d.findings).toHaveLength(0);
    expect(d.inconclusive).toEqual([{ checkId: 'code-security', title: 'INFO finding' }]);
    expect(d.counts.inconclusive).toBe(1);
  });

  it('keeps attack chains in full — they are the analytical payload', () => {
    const chains: AttackChain[] = [{
      id: 'c1',
      title: 'guest to bulk data',
      severity: 'CRITICAL',
      confidence: 'named',
      narrative: 'A long narrative that must survive the digest intact.',
      remediation: 'Break any one step.',
      steps: [{ findingId: 'f1', capability: 'unauthenticated-entry' as AttackChain['steps'][number]['capability'] }],
    }];
    const base = result([]);
    const d = buildDigest({ ...base, attackChains: chains });
    expect(d.attackChains).toEqual(chains);
  });

  it('drops org metrics', () => {
    const d = buildDigest(result([])) as unknown as Record<string, unknown>;
    expect(d.metrics).toBeUndefined();
  });

  it('is materially smaller than the full result', () => {
    const many = [
      ...Array.from({ length: 12 }, () => finding('INFO', { passed: true })),
      ...Array.from({ length: 8 }, () => finding('HIGH', {
        affectedItems: Array.from({ length: 30 }, (_, i) => ({ label: `item${i}` })),
      })),
    ];
    const full = result(many);
    const ratio = JSON.stringify(full).length / JSON.stringify(buildDigest(full)).length;
    expect(ratio).toBeGreaterThan(5);
  });
});
