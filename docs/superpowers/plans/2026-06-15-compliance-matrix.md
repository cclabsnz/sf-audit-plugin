# Compliance Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add the compliance-matrix section (spec §6) to the executive report — per selected framework, list each in-scope verified control with the active findings mapped to it — driven by a `--frameworks universal|nz|all|<list>` selector.

**Architecture:** A pure `buildComplianceMatrix(result, frameworks)` inverts `CHECK_CONTROL_MAP` (verified + selected frameworks only) into framework → control → findings rows; `resolveFrameworks(input)` turns the CLI flag into a `Framework[]`; `ClientReportRenderer` renders it as section 6. Only verified controls appear (provenance gate), so all 89 currently render.

**Tech Stack:** TypeScript ESM (NodeNext, `.js` imports), Jest via `npm test`.

**Scope:** spec §6 only. Compliance data + verification already complete (89/89 verified).

---

### Task 1: resolveFrameworks (pack/alias → Framework[])

**Files:**
- Modify: `src/compliance/resolve.ts`
- Test: `test/unit/compliance/resolveFrameworks.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/compliance/resolveFrameworks.test.ts
import { resolveFrameworks } from '../../../src/compliance/resolve.js';

describe('resolveFrameworks', () => {
  it('resolves pack names', () => {
    expect(resolveFrameworks('universal').sort()).toEqual(['ISO27001', 'OWASP', 'SOC2']);
    expect(resolveFrameworks('nz')).toContain('NZISM');
    expect(resolveFrameworks('all')).toContain('HIPAA');
  });
  it('resolves an explicit comma list of aliases', () => {
    expect(resolveFrameworks('owasp,iso,nzism').sort()).toEqual(['ISO27001', 'NZISM', 'OWASP']);
  });
  it('ignores unknown aliases', () => {
    expect(resolveFrameworks('owasp,bogus')).toEqual(['OWASP']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/compliance/resolveFrameworks.test.ts`
Expected: FAIL — `resolveFrameworks` is not exported.

- [ ] **Step 3: Implement (append to `src/compliance/resolve.ts`)**

```ts
const ALIAS: Record<string, Framework> = {
  owasp: 'OWASP', soc2: 'SOC2', iso: 'ISO27001', iso27001: 'ISO27001', sbs: 'SBS',
  privacy: 'PRIVACY_ACT', 'privacy-act': 'PRIVACY_ACT', hiso: 'HISO10029', nzism: 'NZISM',
  hipaa: 'HIPAA', gdpr: 'GDPR',
};

/** Resolve a --frameworks value: a pack name (universal|nz|all) or a comma list of aliases. */
export function resolveFrameworks(input: string): Framework[] {
  const v = input.trim().toLowerCase();
  if (v === 'universal' || v === 'nz' || v === 'all') return packFrameworks(v);
  const out: Framework[] = [];
  for (const part of v.split(',').map((s) => s.trim())) {
    const fw = ALIAS[part];
    if (fw && !out.includes(fw)) out.push(fw);
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/compliance/resolveFrameworks.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/compliance/resolve.ts test/unit/compliance/resolveFrameworks.test.ts
git commit -m "feat(compliance): resolveFrameworks (pack/alias selector)"
```

---

### Task 2: buildComplianceMatrix

**Files:**
- Create: `src/report/ComplianceMatrix.ts`
- Test: `test/unit/report/ComplianceMatrix.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/report/ComplianceMatrix.test.ts
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
    // internal-user-mfa maps to OWASP-A07; that row should carry finding f1
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/report/ComplianceMatrix.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement**

```ts
// src/report/ComplianceMatrix.ts
import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { ControlDef, Framework } from '../compliance/types.js';
import { CHECK_CONTROL_MAP } from '../compliance/mapping.js';
import { getControl } from '../compliance/catalogs/index.js';

export interface MatrixRow { control: ControlDef; findings: Finding[]; }
export interface FrameworkMatrix { framework: Framework; version: string; rows: MatrixRow[]; }

/** Invert the check→control mapping into framework→control→findings, for verified controls
 *  in the selected frameworks only. A control is "in scope" if any check maps to it. */
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/report/ComplianceMatrix.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/report/ComplianceMatrix.ts test/unit/report/ComplianceMatrix.test.ts
git commit -m "feat(report): buildComplianceMatrix (framework -> control -> findings)"
```

---

### Task 3: Render the matrix in ClientReportRenderer

**Files:**
- Modify: `src/renderers/ClientReportRenderer.ts`
- Modify: `test/unit/renderers/ClientReportRenderer.test.ts`

`ClientReportOptions` gains `frameworks: Framework[]`. The matrix renders as section 6 (after the roadmap, before All Findings). Each framework gets a sub-head + a table: control id · title · status (severity chip of the worst finding, or "No findings"). A framework label names the version.

- [ ] **Step 1: Add a failing assertion to the renderer test**

In `test/unit/renderers/ClientReportRenderer.test.ts`, update the constructor and add a case:

```ts
// change the shared renderer construction to include frameworks:
const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] });

it('renders the compliance matrix for selected frameworks', () => {
  const html = r.render(makeResult());
  expect(html).toContain('Compliance Coverage');
  expect(html).toContain('OWASP-A07');          // a control id in the matrix
  expect(html).toContain('OWASP Top 10:2021');  // the framework version label
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/renderers/ClientReportRenderer.test.ts`
Expected: FAIL — `frameworks` missing from options type / "Compliance Coverage" absent.

- [ ] **Step 3: Implement in `ClientReportRenderer.ts`**

(a) Add imports:
```ts
import type { Framework } from '../compliance/types.js';
import { buildComplianceMatrix, type FrameworkMatrix } from '../report/ComplianceMatrix.js';
```

(b) Extend options:
```ts
export interface ClientReportOptions {
  branding: Branding;
  topN: number;
  frameworks: Framework[];
}
```

(c) In `render`, build the matrix and insert it as a numbered section between roadmap and findings:
```ts
    const matrix = buildComplianceMatrix(result, this.opts.frameworks);
    let n = 0;
    const num = (): string => String(++n).padStart(2, '0');
    const sections = [
      this.summary(result, num()),
      this.prioritiesSection(priorities, chainIds, num()),
      chains.length ? this.scenarios(chains, num()) : '',
      this.roadmapSection(roadmap, num()),
      matrix.length ? this.matrixSection(matrix, num()) : '',
      this.findingsAppendix(result, num()),
    ].join('\n');
```

(d) Add the section renderer and a worst-severity helper:
```ts
  private worst(findings: Finding[]): RiskLevel | undefined {
    return findings.slice().sort((a, b) => SEV_RANK[a.riskLevel] - SEV_RANK[b.riskLevel])[0]?.riskLevel;
  }

  private matrixSection(matrix: FrameworkMatrix[], numStr: string): string {
    const blocks = matrix.map((fm) => {
      const rows = fm.rows.map((row) => {
        const w = this.worst(row.findings);
        const status = w
          ? `${this.chip(w, `${row.findings.length} finding${row.findings.length === 1 ? '' : 's'}`)}`
          : '<span class="muted">No findings detected</span>';
        return `<tr><td class="cid">${esc(row.control.id)}</td><td>${esc(row.control.title)}</td><td class="st">${status}</td></tr>`;
      }).join('');
      return `<h3>${esc(frameworkLabel(fm.framework))} <span class="muted">· ${esc(fm.version)}</span></h3>
<table class="matrix"><thead><tr><th>Control</th><th>Requirement area</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
    }).join('');
    return `${this.sectionHead(numStr, 'Compliance Coverage')}<p class="muted">Findings mapped to framework controls. "No findings detected" is not an attestation of compliance — see Scope &amp; Liability.</p>${blocks}`;
  }
```

(e) Add `SEV_RANK` near `SEV_COLOR`, and a `frameworkLabel` map + matrix CSS:
```ts
const SEV_RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
function frameworkLabel(f: Framework): string {
  return ({ OWASP: 'OWASP Top 10', SOC2: 'SOC 2', ISO27001: 'ISO/IEC 27001', SBS: 'Security Benchmark for Salesforce',
    PRIVACY_ACT: 'NZ Privacy Act', HISO10029: 'HISO 10029', NZISM: 'NZISM', HIPAA: 'HIPAA', GDPR: 'GDPR' } as Record<Framework, string>)[f];
}
```
CSS (add inside the `<style>` block):
```
.matrix{width:100%;border-collapse:collapse;margin:8px 0 18px;font-size:13px}
.matrix th{text-align:left;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.08em;font-size:10px;color:var(--muted);border-bottom:1px solid var(--border);padding:6px 8px}
.matrix td{border-bottom:1px solid var(--border);padding:7px 8px;vertical-align:top}
.matrix .cid{font-family:var(--mono);font-size:12px;color:var(--primary);white-space:nowrap}
.matrix .st{text-align:right;white-space:nowrap}
```

- [ ] **Step 4: Run the renderer test**

Run: `npm test -- test/unit/renderers/ClientReportRenderer.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/renderers/ClientReportRenderer.ts test/unit/renderers/ClientReportRenderer.test.ts
git commit -m "feat(renderers): compliance coverage matrix section"
```

---

### Task 4: Wire `--frameworks` into the command + screenshot

**Files:**
- Modify: `src/commands/audit/security.ts`
- Test: full build + suite + manual render

- [ ] **Step 1: Add the flag**

In `public static flags`, add:
```ts
    frameworks: Flags.string({
      summary: 'Compliance frameworks for the executive matrix: universal | nz | all | a comma list (executive format).',
      default: 'universal',
    }),
```

- [ ] **Step 2: Pass frameworks into the renderer**

(a) Add import:
```ts
import { resolveFrameworks } from '../../compliance/resolve.js';
```
(b) In `rendererFor`, extend the flags type and construction:
```ts
  private rendererFor(
    format: string,
    flags: { 'prepared-for'?: string; branding?: string; top: number; frameworks: string },
  ): AuditRenderer | undefined {
    if (format === 'executive') {
      let overrides: BrandingOverrides | undefined;
      if (flags.branding) overrides = JSON.parse(fs.readFileSync(flags.branding, 'utf-8')) as BrandingOverrides;
      const branding = resolveBranding(overrides, flags['prepared-for']);
      return new ClientReportRenderer({ branding, topN: flags.top, frameworks: resolveFrameworks(flags.frameworks) });
    }
    return RENDERERS[format];
  }
```

- [ ] **Step 3: Build + full suite**

Run: `npm run build && npm test`
Expected: build clean; all suites green.

- [ ] **Step 4: Manual render + screenshot**

Run a render with `frameworks: ['OWASP','NZISM']` (build a sample like Plan 2 Task 7 but add `frameworks` to options), write to `/tmp/exec-report.html`, screenshot with headless Chrome, and read it to confirm the matrix renders cleanly.

- [ ] **Step 5: Commit**

```bash
git add src/commands/audit/security.ts
git commit -m "feat(audit): --frameworks selector wires the compliance matrix"
```

---

### Task 5: Docs

**Files:**
- Modify: `README.md` (add `--frameworks` to the table + a line in the Executive report section)
- Modify: `CLAUDE.md` (note the matrix is now built; remove the "deferred" note)

- [ ] **Step 1: README** — add the `--frameworks` row and mention the matrix renders the verified frameworks.
- [ ] **Step 2: CLAUDE.md** — update the ClientReportRenderer bullet: matrix is implemented; `--frameworks universal|nz|all`.
- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document --frameworks and the compliance matrix"
```

---

## Self-Review

**Spec §6 coverage:** matrix per framework (Task 2/3), control → status with findings (Task 3), framework selection via `--frameworks` packs + list (Task 1/4), provenance gate — only verified controls render (Task 2 `c.verified` guard), "not an attestation" framing in the section copy (Task 3). ✓

**Placeholder scan:** none — all steps have complete code.

**Type consistency:** `Framework` from `compliance/types.js` used in Tasks 1–4. `resolveFrameworks` (Task 1) consumed in Task 4. `buildComplianceMatrix`/`FrameworkMatrix`/`MatrixRow` (Task 2) consumed in Task 3. `ClientReportOptions.frameworks` (Task 3) set by the command (Task 4) and the updated renderer test (Task 3). `SEV_RANK` added once (Task 3). `getControl`/`CHECK_CONTROL_MAP` are existing exports.
