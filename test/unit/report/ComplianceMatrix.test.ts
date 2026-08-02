import { buildComplianceMatrix } from '../../../src/report/ComplianceMatrix.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

function result(findings: AuditResult['findings']): AuditResult {
  return { generatedAt: new Date(), orgId: 'o', orgName: 'o', orgType: 'Production', isSandbox: false,
    instance: 'i', instanceUrl: 'u', healthScore: 50, grade: 'C', metrics: {} as never, findings };
}

describe('buildComplianceMatrix', () => {
  it('groups in-scope verified controls by framework with their active findings', () => {
    const r = result([
      { id: 'f1', checkId: 'internal-user-mfa', category: 'Auth', riskLevel: 'CRITICAL', title: 'no MFA', detail: 'd', remediation: 'r' },
    ]);
    const m = buildComplianceMatrix(r, ['OWASP']);
    const owasp = m.find((x) => x.framework === 'OWASP');
    expect(owasp).toBeDefined();
    const a07 = owasp!.rows.find((row) => row.control.id === 'OWASP-A07');
    expect(a07?.findings.map((f) => f.id)).toContain('f1');
  });

  it('excludes frameworks not selected', () => {
    const m = buildComplianceMatrix(result([]), ['OWASP']);
    expect(m.every((x) => x.framework === 'OWASP')).toBe(true);
  });

  it('ignores passed and inconclusive findings', () => {
    const r = result([
      { id: 'p', checkId: 'internal-user-mfa', category: 'Auth', riskLevel: 'CRITICAL', title: 't', detail: 'd', remediation: 'r', passed: true },
    ]);
    const m = buildComplianceMatrix(r, ['OWASP']);
    const a07 = m.find((x) => x.framework === 'OWASP')!.rows.find((row) => row.control.id === 'OWASP-A07');
    expect(a07?.findings).toEqual([]);
  });
});
