import { buildActionPlan } from '../../../src/report/ActionPlan.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import type { RiskLevel } from '@cclabsnz/sf-core';

const f = (id: string, riskLevel: RiskLevel, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id, category: 'C', riskLevel, title: `T ${id}`, detail: 'd', remediation: `Fix ${id}. Then more.`, ...extra,
});

const chain = (id: string, severity: RiskLevel, steps: Array<[string, boolean?]>, breakPoint?: string): AttackChain => ({
  id, title: id, severity, confidence: breakPoint ? 'named' : 'potential', narrative: 'n', remediation: 'r',
  ...(breakPoint ? { abuseCase: { actor: 'an outsider', goal: 'read data', breakPoint } } : {}),
  steps: steps.map(([findingId, cut]) => ({ findingId, capability: 'data-read', ...(cut ? { breaksChain: true as const } : {}) })),
});

describe('buildActionPlan', () => {
  it('makes one action per break point, closing every break-point finding, and shares it between chains with the same break point', () => {
    const findings = [f('a', 'HIGH'), f('b', 'MEDIUM'), f('c', 'HIGH')];
    const chains = [
      chain('one', 'CRITICAL', [['a', true], ['b', true], ['c']], 'Close the door: lock A and B'),
      chain('two', 'HIGH', [['b', true], ['c']], 'Close the door: lock A and B'),
    ];
    const [action, ...rest] = buildActionPlan(findings, chains);
    expect(action.title).toBe('Close the door');
    expect(action.detail).toBe('Lock A and B');
    expect(action.why).toBe('Stops an outsider who wants to read data.');
    expect(action.breaks).toEqual([0, 1]);
    expect(action.fixes.map((x) => x.id)).toEqual(['a', 'b']);
    expect(action.inChains).toEqual([]);
    // c is HIGH and outside the break point, so it gets its own action, noted as part of both chains.
    expect(rest.map((r) => r.fixes.map((x) => x.id))).toEqual([['c']]);
    expect(rest[0].inChains).toEqual([0, 1]);
    expect(rest[0].title).toBe('Fix c');
  });

  it('only weakens a chain when part of its break point is waived or passed, since fixing the rest leaves it standing', () => {
    const findings = [f('a', 'HIGH'), f('b', 'HIGH', { waived: true }), f('c', 'HIGH', { passed: true })];
    const plan = buildActionPlan(findings, [
      chain('waived', 'CRITICAL', [['a', true], ['b', true]], 'Lock it'),
      chain('passed', 'HIGH', [['a', true], ['c', true]], 'Lock it'),
    ]);
    expect(plan).toHaveLength(1);
    expect(plan[0].breaks).toEqual([]);
    expect(plan[0].weakens).toEqual([0, 1]);
    expect(plan[0].fixes.map((x) => x.id)).toEqual(['a']);
    // Still urgent: it works on a critical chain.
    expect(plan[0].wave).toBe(1);
  });

  it('keeps abbreviations inside the first sentence and never leads with a navigation path', () => {
    const plan = buildActionPlan([
      f('a', 'HIGH', { remediation: 'Set up SSO, e.g. via SAML, for all users. Then test it.' }),
      f('b', 'HIGH', { remediation: 'Setup → Session Settings: enable HttpOnly.' }),
    ], []);
    expect(plan.map((p) => [p.title, p.detail])).toEqual([
      ['Set up SSO, e.g. via SAML, for all users', undefined],
      ['Setup → Session Settings: enable HttpOnly', undefined],
    ]);
  });

  it('skips a chain whose break-point findings are all waived or unassessed, and potential chains', () => {
    const findings = [f('a', 'HIGH', { waived: true }), f('b', 'HIGH', { notAssessed: true }), f('c', 'MEDIUM')];
    const plan = buildActionPlan(findings, [chain('one', 'CRITICAL', [['a', true], ['b', true]], 'Lock it'), chain('p', 'MEDIUM', [['c']])]);
    expect(plan).toEqual([]);
  });

  it('groups standalone CRITICAL and HIGH findings by check, and leaves MEDIUM and LOW to the roadmap', () => {
    const findings = [f('x1', 'HIGH', { checkId: 'x' }), f('x2', 'CRITICAL', { checkId: 'x', remediation: 'Lead fix. More.' }), f('m', 'MEDIUM'), f('l', 'LOW')];
    const plan = buildActionPlan(findings, []);
    expect(plan).toHaveLength(1);
    expect(plan[0].title).toBe('Lead fix');
    expect(plan[0].fixes.map((x) => x.id)).toEqual(['x2', 'x1']);
    expect(plan[0].severity).toBe('CRITICAL');
  });

  it('puts critical work in wave 1, weeks of work in wave 3, and ranks by risk removed within a wave', () => {
    const findings = [
      f('crit', 'CRITICAL'),
      f('high-chain', 'HIGH'),
      f('high', 'HIGH'),
      f('proj', 'HIGH', { checkId: 'sharing-model' }),
    ];
    const plan = buildActionPlan(findings, [chain('c', 'HIGH', [['high-chain', true]], 'Break it')]);
    expect(plan.map((a) => [a.fixes[0].id, a.wave])).toEqual([
      ['crit', 1],
      ['high-chain', 2],
      ['high', 2],
      ['proj', 3],
    ]);
    // Breaking a chain counts its severity twice on top of the finding.
    expect(plan[1].risk).toBe(7 + 2 * 7);
  });
});
