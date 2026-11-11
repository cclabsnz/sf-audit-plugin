import { explain, parseResult, ExplainError } from '../../../src/report/explain.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

const RESULT = {
  metrics: {},
  findings: [
    {
      id: 'apex-no-sharing-declaration', checkId: 'apex-sharing', category: 'c', riskLevel: 'HIGH', title: 'Classes lack a sharing keyword',
      detail: 'Long detail.', remediation: 'Add with sharing.', affectedItems: Array.from({ length: 8 }, (_, i) => ({ label: `Class${i}` })),
    },
    { id: 'apex-sharing-ok', checkId: 'apex-sharing', category: 'c', riskLevel: 'LOW', passed: true, title: 'ok', detail: 'd', remediation: 'r' },
  ],
  attackChains: [{
    id: 'x', title: 'Chain X', severity: 'CRITICAL', confidence: 'named', narrative: 'n', remediation: 'r',
    abuseCase: { actor: 'a', goal: 'g', preconditions: [], breakPoint: 'b' },
    steps: [{ findingId: 'apex-no-sharing-declaration', capability: 'data-read', breaksChain: true }],
  }],
} as unknown as AuditResult;

describe('explain', () => {
  it('explains a check from the registry and its metadata', () => {
    const r = explain('apex-sharing');
    expect(r.check.id).toBe('apex-sharing');
    expect(r.check.domain).toBe('Apex & Code Security');
    expect(r.check.effort).toBeDefined();
    expect(r.check.complianceTags.length).toBeGreaterThan(0);
    expect(r.finding).toBeUndefined();
  });

  it('explains a finding from a run: affected sample, the chain it breaks, and its fix-first action', () => {
    const r = explain('apex-no-sharing-declaration', RESULT);
    expect(r.check.id).toBe('apex-sharing');
    expect(r.finding).toMatchObject({ status: 'open', severity: 'HIGH', affectedCount: 8 });
    expect(r.finding!.affectedSample).toHaveLength(5);
    expect(r.finding!.chains).toEqual([{ label: 'C1', title: 'Chain X', severity: 'CRITICAL', breaksChain: true }]);
    expect(r.finding!.action).toMatchObject({ rank: 1, wave: 'Start now' });
  });

  it("lists a check's findings in a run when given the check id", () => {
    const r = explain('apex-sharing', RESULT);
    expect(r.findings!.map((f) => [f.id, f.status])).toEqual([['apex-no-sharing-declaration', 'open'], ['apex-sharing-ok', 'passed']]);
  });

  it('maps a finding id to its check by the longest matching check id', () => {
    expect(explain('guest-object-exposure-guest-owned').check.id).toBe('guest-object-exposure');
  });

  it('rejects an id that matches no check, and a finding that is not in the run', () => {
    expect(() => explain('no-such-thing')).toThrow(ExplainError);
    expect(() => explain('apex-sharing-missing', RESULT)).toThrow(/is not in this run/);
  });

  it('reads the --json envelope or a bare result, and rejects a digest or summary', () => {
    expect(parseResult(JSON.stringify({ status: 0, result: RESULT })).findings).toHaveLength(2);
    expect(parseResult(JSON.stringify(RESULT)).findings).toHaveLength(2);
    expect(() => parseResult(JSON.stringify({ result: { grade: 'B', actions: [] } }))).toThrow(/not a full audit result/);
    // A digest has findings too, but no ids, detail or metrics.
    const digest = { grade: 'B', counts: {}, findings: [{ checkId: 'apex-sharing', riskLevel: 'HIGH', title: 't', remediation: 'r' }] };
    expect(() => parseResult(JSON.stringify({ result: digest }))).toThrow(/not a full audit result/);
  });

  it('uses the report status rules: waived, inconclusive and informational are not open', () => {
    const r = { ...RESULT, findings: [
      { id: 'w', checkId: 'apex-sharing', riskLevel: 'HIGH', waived: true, title: 't', detail: 'd', remediation: 'r' },
      { id: 'n', checkId: 'apex-sharing', riskLevel: 'HIGH', notAssessed: true, waived: true, title: 't', detail: 'd', remediation: 'r' },
      { id: 'i', checkId: 'apex-sharing', riskLevel: 'INFO', title: 't', detail: 'd', remediation: 'r' },
    ] } as unknown as AuditResult;
    expect(explain('apex-sharing', r).findings!.map((f) => f.status)).toEqual(['waived', 'inconclusive', 'info']);
  });

  it('names the other checks when a finding id appears more than once', () => {
    const dup = { ...RESULT.findings[0], checkId: 'code-security' };
    const r = { ...RESULT, findings: [...RESULT.findings, dup] } as unknown as AuditResult;
    expect(explain('apex-no-sharing-declaration', r).finding!.alsoFrom).toEqual(['code-security']);
  });

  it('explains a finding from an older report whose check is no longer installed', () => {
    const old = { ...RESULT, findings: [{ id: 'retired-thing', checkId: 'retired-check', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r' }] } as unknown as AuditResult;
    const r = explain('retired-thing', old);
    expect(r.check.id).toBe('retired-check');
    expect(r.finding!.id).toBe('retired-thing');
  });
});
