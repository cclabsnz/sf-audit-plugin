import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { ControlDef, Framework } from '../compliance/types.js';
import { CHECK_CONTROL_MAP } from '../compliance/mapping.js';
import { getControl } from '../compliance/catalogs/index.js';

export interface MatrixRow { control: ControlDef; findings: Finding[]; }
export interface FrameworkMatrix { framework: Framework; version: string; rows: MatrixRow[]; }

/**
 * Invert the check→control mapping into framework→control→findings, for verified controls
 * in the selected frameworks only. A control is "in scope" if any check maps to it; its row
 * carries the active (non-passed, non-inconclusive) findings whose check maps to that control.
 */
export function buildComplianceMatrix(result: AuditResult, frameworks: Framework[]): FrameworkMatrix[] {
  const fwSet = new Set(frameworks);
  const active = result.findings.filter((f) => !f.passed && !f.inconclusive);

  const inScope = new Map<string, ControlDef>();
  const hits = new Map<string, Finding[]>();
  for (const controlIds of Object.values(CHECK_CONTROL_MAP)) {
    for (const id of controlIds) {
      const c = getControl(id);
      if (!c || !c.verified || !fwSet.has(c.framework)) continue;
      inScope.set(id, c);
      if (!hits.has(id)) hits.set(id, []);
    }
  }
  for (const f of active) {
    if (!f.checkId) continue;
    for (const id of CHECK_CONTROL_MAP[f.checkId] ?? []) {
      if (hits.has(id)) hits.get(id)!.push(f);
    }
  }

  const byFw = new Map<Framework, MatrixRow[]>();
  for (const [id, control] of inScope) {
    const rows = byFw.get(control.framework) ?? [];
    rows.push({ control, findings: hits.get(id) ?? [] });
    byFw.set(control.framework, rows);
  }

  const out: FrameworkMatrix[] = [];
  for (const fw of frameworks) {
    const rows = byFw.get(fw);
    if (!rows || rows.length === 0) continue;
    rows.sort((a, b) => a.control.id.localeCompare(b.control.id, undefined, { numeric: true }));
    out.push({ framework: fw, version: rows[0].control.version, rows });
  }
  return out;
}
