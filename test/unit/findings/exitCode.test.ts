import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from '../../../src/findings/Finding.js';
import { EXIT_FINDINGS, EXIT_INCONCLUSIVE, EXIT_OK, resolveExitCode, violationsFor } from '../../../src/findings/exitCode.js';

const f = (riskLevel: RiskLevel, extra: Partial<Finding> = {}): Finding => ({
  id: `${riskLevel}-${Math.random()}`,
  category: 'Test',
  riskLevel,
  title: `${riskLevel} finding`,
  detail: 'detail',
  remediation: 'remediation',
  ...extra,
});

describe('violationsFor', () => {
  it('does not treat INFO findings as violations at the CRITICAL threshold', () => {
    // ORDER.indexOf('INFO') is -1, and -1 <= threshold is true for every threshold.
    // That made every passing check a violation, so --fail-on fired on every audit.
    expect(violationsFor([f('INFO')], 'CRITICAL')).toHaveLength(0);
  });

  it('does not treat INFO findings as violations at any threshold', () => {
    for (const failOn of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as RiskLevel[]) {
      expect(violationsFor([f('INFO')], failOn)).toHaveLength(0);
    }
  });

  it('never counts a passed finding as a violation', () => {
    expect(violationsFor([f('INFO', { passed: true })], 'LOW')).toHaveLength(0);
  });

  it('never counts an inconclusive finding as a violation', () => {
    expect(violationsFor([f('INFO', { inconclusive: true })], 'LOW')).toHaveLength(0);
  });

  it('counts a finding at the threshold', () => {
    expect(violationsFor([f('HIGH')], 'HIGH')).toHaveLength(1);
  });

  it('counts a finding above the threshold', () => {
    expect(violationsFor([f('CRITICAL')], 'HIGH')).toHaveLength(1);
  });

  it('does not count a finding below the threshold', () => {
    expect(violationsFor([f('MEDIUM')], 'HIGH')).toHaveLength(0);
  });
});

describe('resolveExitCode', () => {
  it('is 0 when no threshold is requested, even with a CRITICAL finding', () => {
    expect(resolveExitCode([f('CRITICAL')], {})).toBe(EXIT_OK);
  });

  it('is 0 when findings sit below the threshold', () => {
    expect(resolveExitCode([f('MEDIUM')], { failOn: 'HIGH' })).toBe(EXIT_OK);
  });

  it('is 1 when a finding meets the threshold', () => {
    expect(resolveExitCode([f('HIGH')], { failOn: 'HIGH' })).toBe(EXIT_FINDINGS);
  });

  it('is 0 for inconclusive findings when the caller has not opted in', () => {
    expect(resolveExitCode([f('INFO', { inconclusive: true })], {})).toBe(EXIT_OK);
  });

  it('is 3 for inconclusive findings when the caller opts in', () => {
    expect(resolveExitCode([f('INFO', { inconclusive: true })], { failOnInconclusive: true })).toBe(EXIT_INCONCLUSIVE);
  });

  it('prefers the definite finding over the unknown when both apply', () => {
    const findings = [f('CRITICAL'), f('INFO', { inconclusive: true })];
    expect(resolveExitCode(findings, { failOn: 'HIGH', failOnInconclusive: true })).toBe(EXIT_FINDINGS);
  });

  it('is 0 for a clean audit of passes only', () => {
    expect(resolveExitCode([f('INFO', { passed: true })], { failOn: 'LOW', failOnInconclusive: true })).toBe(EXIT_OK);
  });
});
