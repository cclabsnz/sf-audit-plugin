import { buildAuditResult } from '../../../src/findings/scoring.js';
import { evidenceCoverage, coverageSummary, MIN_COVERAGE_FOR_A } from '../../../src/findings/coverage.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const ctx = {
  soql: {}, tooling: {}, rest: {}, cache: {},
  orgInfo: { id: '00Dxx0000000000EAA', name: 'Acme', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
} as unknown as AuditContext;

const pass = (checkId: string): Finding => ({
  id: `${checkId}-ok`, checkId, category: 'c', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r', passed: true,
});
const blind = (checkId: string): Finding => ({
  id: `${checkId}-error`, checkId, category: 'c', riskLevel: 'INFO', title: 't', detail: 'd', remediation: 'r', inconclusive: true, notAssessed: true,
});
const checks = (n: number, make: (id: string) => Finding, from = 0) =>
  Array.from({ length: n }, (_, i) => make(`check-${String(i + from).padStart(2, '0')}`));

describe('evidenceCoverage', () => {
  it('counts checks, not findings: one blind check with three inconclusive findings is one gap', () => {
    const three = [blind('a'), { ...blind('a'), id: 'a-2' }, { ...blind('a'), id: 'a-3' }];
    const c = evidenceCoverage([...three, pass('b'), pass('c'), pass('d')]);
    expect(c).toEqual({ checksRun: 4, checksAssessed: 3, percent: 75, notAssessed: ['a'] });
  });

  it('treats a check with some evidence and some gaps as assessed', () => {
    const c = evidenceCoverage([pass('a'), { ...blind('a'), id: 'a-partial', notAssessed: undefined }]);
    expect(c.notAssessed).toEqual([]);
    expect(c.percent).toBe(100);
  });

  it('counts a crashed check (not a permission error) as not assessed', () => {
    const crashed: Finding = { ...blind('x'), inconclusive: undefined };
    expect(evidenceCoverage([crashed, pass('y')]).notAssessed).toEqual(['x']);
  });

  it('is 100% for an empty run', () => {
    expect(evidenceCoverage([]).percent).toBe(100);
  });

  it('rounds down, so 89.9% never reads as 90%', () => {
    const c = evidenceCoverage([...checks(899, pass), ...checks(101, blind, 899)]);
    expect(c.percent).toBe(89);
  });
});

describe('grade cap', () => {
  it('caps a would-be A at B when coverage is below the bar, and says so', () => {
    const r = buildAuditResult(ctx, [...checks(10, pass), ...checks(10, blind, 10)], {});
    expect(r.grade).toBe('B');
    expect(r.coverage?.gradeCapped).toBe(true);
    expect(r.coverage?.percent).toBe(50);
    expect(coverageSummary(r.coverage!)).toContain('grade capped at B');
  });

  it('awards an A at exactly the bar', () => {
    const r = buildAuditResult(ctx, [...checks(MIN_COVERAGE_FOR_A, pass), ...checks(100 - MIN_COVERAGE_FOR_A, blind, MIN_COVERAGE_FOR_A)], {});
    expect(r.coverage?.percent).toBe(MIN_COVERAGE_FOR_A);
    expect(r.grade).toBe('A');
    expect(r.coverage?.gradeCapped).toBe(false);
  });

  it('leaves grades below A alone: coverage never raises or lowers a B or worse', () => {
    const findings: Finding[] = [
      ...checks(5, pass),
      ...checks(5, blind, 5),
      { id: 'h', checkId: 'h', category: 'c', riskLevel: 'HIGH', title: 't', detail: 'd', remediation: 'r' },
    ];
    const r = buildAuditResult(ctx, findings, {});
    expect(r.grade).not.toBe('A');
    expect(r.coverage?.gradeCapped).toBe(false);
  });

  it('keeps grade a plain letter so history, diff and JSON consumers are unaffected', () => {
    const r = buildAuditResult(ctx, [...checks(1, pass), ...checks(9, blind, 1)], {});
    expect(['A', 'B', 'C', 'D', 'F']).toContain(r.grade);
  });
});
