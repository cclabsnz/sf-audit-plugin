import { buildRoadmap } from '../../../src/report/RemediationRoadmap.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(over: Partial<Finding>): Finding {
  return { id: 'x', checkId: 'internal-user-mfa', category: 'c', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r', ...over } as Finding;
}

describe('buildRoadmap', () => {
  it('groups by effort tier and risk-sorts within a tier', () => {
    const findings = [
      f({ id: 'a', checkId: 'internal-user-mfa', riskLevel: 'LOW' }),       // quick
      f({ id: 'b', checkId: 'internal-user-mfa', riskLevel: 'CRITICAL' }),  // quick
      f({ id: 'c', checkId: 'sharing-model', riskLevel: 'HIGH' }),          // project
    ];
    const r = buildRoadmap(findings);
    expect(r.quick.map((x) => x.id)).toEqual(['b', 'a']);
    expect(r.project.map((x) => x.id)).toEqual(['c']);
    expect(r.moderate).toEqual([]);
  });

  it('excludes passed/inconclusive and defaults unknown checkId to moderate', () => {
    const findings = [
      f({ id: 'p', passed: true }),
      f({ id: 'u', checkId: 'no-such-check', riskLevel: 'HIGH' }),
    ];
    const r = buildRoadmap(findings);
    expect(r.quick.concat(r.moderate, r.project).map((x) => x.id)).toEqual(['u']);
    expect(r.moderate.map((x) => x.id)).toEqual(['u']);
  });
});
