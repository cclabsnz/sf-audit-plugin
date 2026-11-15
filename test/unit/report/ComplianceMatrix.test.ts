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

// spec/nz-compliance-crosswalk.md RULE-127: HISO and NZISM rows list only the findings that evidence them.
import { CHECK_NZ_CITATIONS } from '../../../src/compliance/nz/citations.generated.js';
import { complianceTagsForFinding } from '../../../src/compliance/mapping.js';

describe('buildComplianceMatrix with per-finding NZ citations', () => {
  const finding = (checkId: string, id: string, riskLevel: 'HIGH' | 'INFO') =>
    ({ id, checkId, category: 'c', riskLevel, title: id, detail: 'd', remediation: 'r', complianceTags: complianceTagsForFinding(checkId, { id, riskLevel }) });

  it('a scoped HSUP row lists the named finding and not the check\'s other findings', () => {
    const entry = Object.entries(CHECK_NZ_CITATIONS).find(([, c]) => c.hsup.some((h) => h.findings && !c.hsup.some((x) => x.id === h.id && !x.findings)));
    expect(entry).toBeDefined();
    const [check, c] = entry!;
    const h = c.hsup.find((x) => x.findings)!;
    const r = result([finding(check, h.findings![0], 'HIGH'), finding(check, 'zz-other-finding', 'HIGH')]);
    const row = buildComplianceMatrix(r, ['HISO10029_4']).flatMap((m) => m.rows).find((x) => x.control.id === `HISO-${h.id}`);
    expect(row?.findings.map((f) => f.id)).toEqual([h.findings![0]]);
  });

  it('an INFO finding is in no HISO or NZISM row but still in its other framework rows', () => {
    const r = result([finding('mfa-enforcement', 'mfa-enforcement-x', 'INFO')]);
    const nz = buildComplianceMatrix(r, ['HISO10029_3', 'HISO10029_4', 'NZISM']).flatMap((m) => m.rows);
    expect(nz.every((row) => row.findings.length === 0)).toBe(true);
    const iso = buildComplianceMatrix(r, ['ISO27001']).flatMap((m) => m.rows);
    expect(iso.some((row) => row.findings.length === 1)).toBe(true);
  });
});
