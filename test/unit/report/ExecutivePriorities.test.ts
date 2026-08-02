import { selectPriorities } from '../../../src/report/ExecutivePriorities.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(over: Partial<Finding>): Finding {
  return { id: 'x', category: 'c', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r', ...over } as Finding;
}

describe('selectPriorities', () => {
  it('orders by severity and caps at topN', () => {
    const findings = [
      f({ id: 'low', riskLevel: 'LOW', title: 'low' }),
      f({ id: 'crit', riskLevel: 'CRITICAL', title: 'crit' }),
      f({ id: 'high', riskLevel: 'HIGH', title: 'high' }),
    ];
    const out = selectPriorities(findings, new Set(), 2);
    expect(out.map((p) => p.id)).toEqual(['crit', 'high']);
  });

  it('excludes passed and inconclusive findings', () => {
    const findings = [
      f({ id: 'ok', riskLevel: 'CRITICAL', passed: true }),
      f({ id: 'incon', riskLevel: 'CRITICAL', inconclusive: true }),
      f({ id: 'real', riskLevel: 'HIGH' }),
    ];
    const out = selectPriorities(findings, new Set(), 5);
    expect(out.map((p) => p.id)).toEqual(['real']);
  });

  it('ranks chain-participating findings above equal-severity non-chain', () => {
    const findings = [
      f({ id: 'plain', riskLevel: 'HIGH', title: 'plain' }),
      f({ id: 'chained', riskLevel: 'HIGH', title: 'chained' }),
    ];
    const out = selectPriorities(findings, new Set(['chained']), 5);
    expect(out[0].id).toBe('chained');
  });
});
