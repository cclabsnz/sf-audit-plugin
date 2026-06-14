# Executive Report Renderer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--format executive` renderer that produces a self-contained, CloudCounsel-branded, print-to-PDF HTML report: cover + grade, executive summary, top-N priorities with abuse/impact narratives, attack scenarios, a risk×effort remediation roadmap, full findings, and a scope/liability footer.

**Architecture:** A new `ClientReportRenderer` (implements the existing `AuditRenderer`) assembles small, independently-tested report modules (`branding`, `ExecutivePriorities`, `RemediationRoadmap`) plus the existing `AttackChain` data into one self-contained HTML document with embedded fonts and print CSS. The command constructs it at runtime from new flags. Compliance matrix (section 6 of the spec) is deferred to a later plan (gated on control verification).

**Tech Stack:** TypeScript ESM (NodeNext — relative imports end in `.js`), Jest via `npm test`, `@salesforce/sf-plugins-core` flags. Fonts: DM Sans + DM Serif Display woff2 embedded as base64 data URIs.

**Scope:** spec `docs/superpowers/specs/2026-06-14-executive-compliance-report-design.md`, sections 1–5, 7–8 (NOT section 6 compliance matrix). `CheckMeta` (effort/impact) and the compliance resolve layer already exist from the prior plan.

---

### Task 1: Extract shared HTML escape/util into one module

**Files:**
- Create: `src/renderers/html-utils.ts`
- Modify: `src/renderers/HtmlRenderer.ts` (import `esc` from the new module, remove the local copy)
- Test: `test/unit/renderers/html-utils.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/renderers/html-utils.test.ts
import { esc } from '../../../src/renderers/html-utils.js';

describe('esc', () => {
  it('escapes HTML-significant characters', () => {
    expect(esc('<a href="x">&')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;');
  });
  it('returns plain text unchanged', () => {
    expect(esc('plain text 123')).toBe('plain text 123');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/renderers/html-utils.test.ts`
Expected: FAIL — cannot find module `html-utils.js`.

- [ ] **Step 3: Create the util**

```ts
// src/renderers/html-utils.ts
export function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
```

- [ ] **Step 4: Refactor HtmlRenderer to import it**

In `src/renderers/HtmlRenderer.ts`: delete the local `function esc(...) { ... }` definition and add near the top imports:

```ts
import { esc } from './html-utils.js';
```

- [ ] **Step 5: Run tests to verify pass + no regression**

Run: `npm test -- test/unit/renderers/html-utils.test.ts test/unit/renderers/HtmlRenderer.test.ts`
Expected: PASS for both (HtmlRenderer output unchanged — `esc` behaviour is identical).

- [ ] **Step 6: Commit**

```bash
git add src/renderers/html-utils.ts src/renderers/HtmlRenderer.ts test/unit/renderers/html-utils.test.ts
git commit -m "refactor(renderers): extract shared esc html util"
```

---

### Task 2: Branding module (defaults + override merge)

**Files:**
- Create: `src/report/branding.ts`
- Test: `test/unit/report/branding.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/report/branding.test.ts
import { resolveBranding, DEFAULT_BRANDING } from '../../../src/report/branding.js';

describe('resolveBranding', () => {
  it('returns CloudCounsel defaults when no overrides', () => {
    const b = resolveBranding(undefined, undefined);
    expect(b.firmName).toBe('CloudCounsel Limited');
    expect(b.primary).toBe('#3a5a82');
    expect(b.fontBody).toBe('DM Sans');
  });

  it('applies overrides over defaults', () => {
    const b = resolveBranding({ primary: '#000000', firmName: 'Acme' }, 'Client X');
    expect(b.primary).toBe('#000000');
    expect(b.firmName).toBe('Acme');
    expect(b.preparedFor).toBe('Client X');
    expect(b.fontBody).toBe(DEFAULT_BRANDING.fontBody); // untouched default
  });

  it('preparedFor argument wins over file value', () => {
    const b = resolveBranding({ preparedFor: 'File Co' }, 'Flag Co');
    expect(b.preparedFor).toBe('Flag Co');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/report/branding.test.ts`
Expected: FAIL — cannot find module `branding.js`.

- [ ] **Step 3: Implement branding**

```ts
// src/report/branding.ts
export interface Branding {
  firmName: string;
  primary: string;       // hex
  ink: string;
  bg: string;
  bgAlt: string;
  muted: string;
  border: string;
  fontDisplay: string;
  fontBody: string;
  contact: string;
  logoPath?: string;
  preparedFor?: string;
}

export const DEFAULT_BRANDING: Branding = {
  firmName: 'CloudCounsel Limited',
  primary: '#3a5a82',
  ink: '#1a1d24',
  bg: '#faf6ef',
  bgAlt: '#f7f7f2',
  muted: '#636770',
  border: '#e9e9e3',
  fontDisplay: 'DM Serif Display',
  fontBody: 'DM Sans',
  contact: 'hello@cloudcounsel.co.nz',
};

export type BrandingOverrides = Partial<Branding>;

export function resolveBranding(overrides: BrandingOverrides | undefined, preparedFor: string | undefined): Branding {
  const merged: Branding = { ...DEFAULT_BRANDING, ...(overrides ?? {}) };
  if (preparedFor) merged.preparedFor = preparedFor;
  return merged;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/report/branding.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/report/branding.ts test/unit/report/branding.test.ts
git commit -m "feat(report): branding defaults + override merge"
```

---

### Task 3: Embed brand fonts as base64 data URIs

**Files:**
- Create: `src/assets/fonts/` (copy 4 woff2 files in)
- Create: `src/report/fonts.ts`
- Modify: `package.json` (`files` array — add `/src/assets` so woff2 ship)
- Test: `test/unit/report/fonts.test.ts`

- [ ] **Step 1: Copy the 4 woff2 into the package**

Run:
```bash
mkdir -p src/assets/fonts
cp "../cloudcounsel-website/public/fonts/dm-sans-normal-latin.woff2" src/assets/fonts/
cp "../cloudcounsel-website/public/fonts/dm-sans-italic-latin.woff2" src/assets/fonts/
cp "../cloudcounsel-website/public/fonts/dm-serif-display-normal-latin.woff2" src/assets/fonts/
cp "../cloudcounsel-website/public/fonts/dm-serif-display-italic-latin.woff2" src/assets/fonts/
ls src/assets/fonts/
```
Expected: 4 `.woff2` files listed.

- [ ] **Step 2: Write the failing test**

```ts
// test/unit/report/fonts.test.ts
import { fontFaceCss } from '../../../src/report/fonts.js';

describe('fontFaceCss', () => {
  it('emits @font-face blocks with embedded woff2 data URIs', () => {
    const css = fontFaceCss();
    expect(css).toContain('@font-face');
    expect(css).toContain("font-family: 'DM Sans'");
    expect(css).toContain("font-family: 'DM Serif Display'");
    expect(css).toContain('data:font/woff2;base64,');
    // no external references — fully self-contained
    expect(css).not.toContain('http');
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npm test -- test/unit/report/fonts.test.ts`
Expected: FAIL — cannot find module `fonts.js`.

- [ ] **Step 4: Implement fonts loader (reads woff2 relative to module, base64-embeds)**

```ts
// src/report/fonts.ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
// compiled location is lib/report/, source assets ship under src/assets — resolve via package root
const FONT_DIR = join(HERE, '..', '..', 'src', 'assets', 'fonts');

function dataUri(file: string): string {
  const buf = readFileSync(join(FONT_DIR, file));
  return `data:font/woff2;base64,${buf.toString('base64')}`;
}

function face(family: string, style: string, file: string): string {
  return `@font-face{font-family:'${family}';font-style:${style};font-display:swap;src:url(${dataUri(file)}) format('woff2');}`;
}

export function fontFaceCss(): string {
  return [
    face('DM Sans', 'normal', 'dm-sans-normal-latin.woff2'),
    face('DM Sans', 'italic', 'dm-sans-italic-latin.woff2'),
    face('DM Serif Display', 'normal', 'dm-serif-display-normal-latin.woff2'),
    face('DM Serif Display', 'italic', 'dm-serif-display-italic-latin.woff2'),
  ].join('\n');
}
```

- [ ] **Step 5: Add assets to package files**

In `package.json` `files` array, add `"/src/assets"` (so the woff2 ship in the published package). Keep existing entries.

- [ ] **Step 6: Run test to verify it passes**

Run: `npm test -- test/unit/report/fonts.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/assets/fonts src/report/fonts.ts package.json test/unit/report/fonts.test.ts
git commit -m "feat(report): embed DM Sans + DM Serif Display as base64 @font-face"
```

---

### Task 4: Executive priorities selection

**Files:**
- Create: `src/report/ExecutivePriorities.ts`
- Test: `test/unit/report/ExecutivePriorities.test.ts`

Priority order: by risk weight (CRITICAL>HIGH>MEDIUM>LOW>INFO), then findings that participate in an attack chain ranked above those that don't, then stable by title. Excludes passed and inconclusive findings. Caps at `topN`.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/report/ExecutivePriorities.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/report/ExecutivePriorities.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement**

```ts
// src/report/ExecutivePriorities.ts
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '../findings/RiskLevel.js';

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/** chainFindingIds: ids of findings that appear in any attack chain step. */
export function selectPriorities(findings: Finding[], chainFindingIds: Set<string>, topN: number): Finding[] {
  return findings
    .filter((f) => !f.passed && !f.inconclusive)
    .slice()
    .sort((a, b) => {
      if (RANK[a.riskLevel] !== RANK[b.riskLevel]) return RANK[a.riskLevel] - RANK[b.riskLevel];
      const ac = chainFindingIds.has(a.id) ? 0 : 1;
      const bc = chainFindingIds.has(b.id) ? 0 : 1;
      if (ac !== bc) return ac - bc;
      return a.title.localeCompare(b.title);
    })
    .slice(0, topN);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/report/ExecutivePriorities.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/report/ExecutivePriorities.ts test/unit/report/ExecutivePriorities.test.ts
git commit -m "feat(report): executive priorities selection (risk + chain weighting)"
```

---

### Task 5: Remediation roadmap grouping

**Files:**
- Create: `src/report/RemediationRoadmap.ts`
- Test: `test/unit/report/RemediationRoadmap.test.ts`

Groups active findings into Quick wins / Moderate / Projects using `CheckMeta.effort` (looked up via `getCheckMeta(finding.checkId)`); within each tier, risk-sorted. Findings without a CheckMeta entry default to `moderate`.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/report/RemediationRoadmap.test.ts
import { buildRoadmap } from '../../../src/report/RemediationRoadmap.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(over: Partial<Finding>): Finding {
  return { id: 'x', checkId: 'internal-user-mfa', category: 'c', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r', ...over } as Finding;
}

describe('buildRoadmap', () => {
  it('groups by effort tier and risk-sorts within a tier', () => {
    const findings = [
      f({ id: 'a', checkId: 'internal-user-mfa', riskLevel: 'LOW' }),   // quick
      f({ id: 'b', checkId: 'internal-user-mfa', riskLevel: 'CRITICAL' }), // quick
      f({ id: 'c', checkId: 'sharing-model', riskLevel: 'HIGH' }),       // project
    ];
    const r = buildRoadmap(findings);
    expect(r.quick.map((x) => x.id)).toEqual(['b', 'a']); // crit before low
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/report/RemediationRoadmap.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement**

```ts
// src/report/RemediationRoadmap.ts
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '../findings/RiskLevel.js';
import { getCheckMeta } from '../findings/CheckMeta.js';

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export interface Roadmap {
  quick: Finding[];
  moderate: Finding[];
  project: Finding[];
}

export function buildRoadmap(findings: Finding[]): Roadmap {
  const out: Roadmap = { quick: [], moderate: [], project: [] };
  for (const f of findings) {
    if (f.passed || f.inconclusive) continue;
    const effort = (f.checkId && getCheckMeta(f.checkId)?.effort) || 'moderate';
    out[effort].push(f);
  }
  const sort = (arr: Finding[]): Finding[] => arr.sort((a, b) => RANK[a.riskLevel] - RANK[b.riskLevel]);
  sort(out.quick); sort(out.moderate); sort(out.project);
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/report/RemediationRoadmap.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/report/RemediationRoadmap.ts test/unit/report/RemediationRoadmap.test.ts
git commit -m "feat(report): remediation roadmap grouping by effort tier"
```

---

### Task 6: ClientReportRenderer — assemble the report

**Files:**
- Create: `src/renderers/ClientReportRenderer.ts`
- Test: `test/unit/renderers/ClientReportRenderer.test.ts`

The renderer takes branding + topN in its constructor and implements `AuditRenderer`. It renders sections: cover, executive summary, top-N priorities (with `getCheckMeta(checkId).impact` and chain note), attack scenarios (`result.attackChains`), remediation roadmap, full findings, scope footer. Self-contained: embeds `fontFaceCss()` and inline styles from branding.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/renderers/ClientReportRenderer.test.ts
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from '../../../src/report/branding.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

function makeResult(): AuditResult {
  return {
    generatedAt: new Date('2026-06-14T00:00:00Z'),
    orgId: '00Dxx', orgName: 'Acme', orgType: 'Production', isSandbox: false,
    instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com',
    healthScore: 62, grade: 'C',
    metrics: {} as never,
    findings: [
      { id: 'f1', checkId: 'internal-user-mfa', category: 'Authentication', riskLevel: 'CRITICAL',
        title: '3 admins without MFA', detail: 'd', remediation: 'Enforce MFA', complianceTags: ['OWASP-A07'] },
      { id: 'f2', checkId: 'sharing-model', category: 'Data', riskLevel: 'HIGH',
        title: 'Loose OWD', detail: 'd', remediation: 'Tighten OWD' },
    ],
    attackChains: [
      { id: 'c1', title: 'Account takeover', severity: 'CRITICAL', confidence: 'named',
        narrative: 'Stolen password to full org access.', remediation: 'Enforce MFA',
        steps: [{ findingId: 'f1', capability: 'INITIAL_ACCESS' as never, title: '3 admins without MFA', severity: 'CRITICAL' }] },
    ],
  };
}

describe('ClientReportRenderer', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5 });

  it('declares the executive format and html extension', () => {
    expect(r.format).toBe('executive');
    expect(r.fileExtension).toBe('.html');
    expect(r.filenamePrefix).toBe('SF_Audit_Executive');
  });

  it('renders a self-contained branded report with all sections', () => {
    const html = r.render(makeResult());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('CloudCounsel Limited');
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Executive Priorities');
    expect(html).toContain('Attack Scenarios');
    expect(html).toContain('Remediation Roadmap');
    expect(html).toContain('Grade');
    expect(html).toContain('Account takeover');           // chain narrative
    expect(html).toContain('@font-face');                 // fonts embedded
    expect(html).not.toContain('http://');                // self-contained, no http refs
  });

  it('shows the per-check impact narrative for a priority', () => {
    const html = r.render(makeResult());
    expect(html).toContain('no second factor');           // internal-user-mfa impact line
  });

  it('escapes finding titles', () => {
    const res = makeResult();
    res.findings[0].title = '<script>x</script>';
    expect(r.render(res)).not.toContain('<script>x</script>');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/renderers/ClientReportRenderer.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the renderer**

```ts
// src/renderers/ClientReportRenderer.ts
import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditRenderer } from './AuditRenderer.js';
import type { Branding } from '../report/branding.js';
import { esc } from './html-utils.js';
import { fontFaceCss } from '../report/fonts.js';
import { getCheckMeta } from '../findings/CheckMeta.js';
import { selectPriorities } from '../report/ExecutivePriorities.js';
import { buildRoadmap } from '../report/RemediationRoadmap.js';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#7d3a3a', HIGH: '#a35a2a', MEDIUM: '#8a6d1f', LOW: '#3a5a82', INFO: '#636770',
};

export interface ClientReportOptions {
  branding: Branding;
  topN: number;
}

export class ClientReportRenderer implements AuditRenderer {
  public readonly format = 'executive';
  public readonly fileExtension = '.html';
  public readonly filenamePrefix = 'SF_Audit_Executive';

  public constructor(private readonly opts: ClientReportOptions) {}

  public render(result: AuditResult): string {
    const b = this.opts.branding;
    const chainIds = new Set<string>();
    for (const c of result.attackChains ?? []) for (const s of c.steps) chainIds.add(s.findingId);
    const priorities = selectPriorities(result.findings, chainIds, this.opts.topN);
    const roadmap = buildRoadmap(result.findings);

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security Audit — ${esc(result.orgName)}</title>
<style>${fontFaceCss()}
:root{--ink:${b.ink};--bg:${b.bg};--bgalt:${b.bgAlt};--muted:${b.muted};--border:${b.border};--primary:${b.primary};}
*{box-sizing:border-box}
body{font-family:'${b.fontBody}',system-ui,sans-serif;color:var(--ink);background:var(--bg);margin:0;line-height:1.55}
.wrap{max-width:820px;margin:0 auto;padding:48px 40px}
h1,h2,h3{font-family:'${b.fontDisplay}',Georgia,serif;letter-spacing:-0.01em;line-height:1.15}
h1{font-size:34px;margin:0 0 4px} h2{font-size:24px;margin:40px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}
h3{font-size:18px;margin:18px 0 4px}
.eyebrow{font-family:'${b.fontDisplay}',serif;color:var(--primary);font-size:13px}
.grade{font-family:'${b.fontDisplay}',serif;font-size:64px;color:var(--primary);line-height:1}
.muted{color:var(--muted)} .sev{font-weight:700;font-size:12px}
.card{background:var(--bgalt);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin:10px 0}
.tier{font-family:'${b.fontDisplay}',serif;color:var(--primary);margin-top:14px}
footer{margin-top:48px;border-top:1px solid var(--border);padding-top:16px;color:var(--muted);font-size:12px}
@page{margin:18mm} @media print{.wrap{padding:0}h2{break-after:avoid}.card{break-inside:avoid}}
</style></head><body><div class="wrap">
${this.cover(result, b)}
${this.summary(result)}
${this.prioritiesSection(priorities, chainIds, result)}
${this.scenarios(result)}
${this.roadmapSection(roadmap)}
${this.findingsAppendix(result)}
${this.footer(b)}
</div></body></html>`;
  }

  private cover(r: AuditResult, b: Branding): string {
    const prepared = b.preparedFor ? ` for ${esc(b.preparedFor)}` : '';
    return `<header><div class="eyebrow">${esc(b.firmName)}</div>
<h1>Salesforce Security Audit</h1>
<p class="muted">${esc(r.orgName)} · ${esc(r.orgType)} · ${esc(r.orgId)} · ${r.generatedAt.toISOString().slice(0, 10)}</p>
<div class="grade">${esc(r.grade)}</div><p class="muted">Health score ${r.healthScore}/100 · Prepared by ${esc(b.firmName)}${prepared}</p></header>`;
  }

  private summary(r: AuditResult): string {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
    const counts = levels.map((l) => `${r.findings.filter((f) => f.riskLevel === l && !f.passed && !f.inconclusive).length} ${l}`).join(' · ');
    const incon = r.findings.filter((f) => f.inconclusive).length;
    return `<h2>Executive Summary</h2><p>This audit assessed the org’s security configuration and scored it <strong>${r.healthScore}/100 (Grade ${esc(r.grade)})</strong>. Findings by severity: ${counts}${incon ? ` · ${incon} inconclusive` : ''}. The priorities below are the highest-impact items to address first; see Scope &amp; Liability for the basis and limits of this assessment.</p>`;
  }

  private prioritiesSection(priorities: Finding[], chainIds: Set<string>, _r: AuditResult): string {
    if (priorities.length === 0) return '<h2>Executive Priorities</h2><p class="muted">No active findings.</p>';
    const items = priorities.map((f, i) => {
      const meta = f.checkId ? getCheckMeta(f.checkId) : undefined;
      const chained = chainIds.has(f.id) ? '<p class="muted">Part of an attack chain — see Attack Scenarios.</p>' : '';
      const impact = meta ? `<p><strong>Impact:</strong> ${esc(meta.impact)}</p>` : '';
      return `<div class="card"><h3>${i + 1}. ${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span></h3>
${impact}${chained}<p><strong>Fix:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `<h2>Executive Priorities</h2><p class="muted">Focus areas, highest impact first.</p>${items}`;
  }

  private scenarios(r: AuditResult): string {
    const chains = r.attackChains ?? [];
    if (chains.length === 0) return '';
    const items = chains.map((c) => `<div class="card"><h3>${esc(c.title)} <span class="sev" style="color:${SEV_COLOR[c.severity]}">${c.severity}</span></h3>
<p>${esc(c.narrative)}</p><p><strong>Breaks the chain:</strong> ${esc(c.remediation)}</p></div>`).join('');
    return `<h2>Attack Scenarios</h2><p class="muted">How findings combine into real attack paths.</p>${items}`;
  }

  private roadmapSection(roadmap: { quick: Finding[]; moderate: Finding[]; project: Finding[] }): string {
    const tier = (label: string, arr: Finding[]): string => {
      if (arr.length === 0) return '';
      const rows = arr.map((f) => `<li>${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span></li>`).join('');
      return `<div class="tier">${label}</div><ul>${rows}</ul>`;
    };
    return `<h2>Remediation Roadmap</h2>
${tier('Quick wins (≤1 day)', roadmap.quick)}
${tier('Moderate (days)', roadmap.moderate)}
${tier('Projects (weeks)', roadmap.project)}`;
  }

  private findingsAppendix(r: AuditResult): string {
    const rows = r.findings.map((f) => {
      const tag = f.inconclusive ? ' <span class="muted">(inconclusive)</span>' : f.passed ? ' <span class="muted">(passed)</span>' : '';
      return `<div class="card"><h3>${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span>${tag}</h3>
<p>${esc(f.detail)}</p><p class="muted"><strong>Remediation:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `<h2>All Findings</h2>${rows}`;
  }

  private footer(b: Branding): string {
    return `<footer><strong>Scope &amp; Liability.</strong> Read-only, point-in-time configuration review — not a penetration test, not a code audit. The grade is a prioritisation aid, not a certification. Validate findings before remediation. © ${new Date().getFullYear()} ${esc(b.firmName)} · ${esc(b.contact)}</footer>`;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/renderers/ClientReportRenderer.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/renderers/ClientReportRenderer.ts test/unit/renderers/ClientReportRenderer.test.ts
git commit -m "feat(renderers): executive client report renderer (sections 1-5,7-8)"
```

---

### Task 7: Wire `executive` into the command + flags + filename

**Files:**
- Modify: `src/renderers/AuditRenderer.ts` (add optional `filenamePrefix`)
- Modify: `src/commands/audit/security.ts` (flags, runtime renderer construction, filename prefix)
- Test: `test/unit/renderers/AuditRenderer-prefix.test.ts` (interface usage smoke) — see Step 1

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/renderers/AuditRenderer-prefix.test.ts
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from '../../../src/report/branding.js';

it('exposes a filenamePrefix the command can use to avoid collisions', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5 });
  const prefix: string = r.filenamePrefix ?? 'sf-audit';
  expect(prefix).toBe('SF_Audit_Executive');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/renderers/AuditRenderer-prefix.test.ts`
Expected: FAIL — TypeScript error: `filenamePrefix` not on `AuditRenderer` (the renderer declares it but the interface doesn't yet, and the import chain compiles the interface). If it passes already because the class declares it, proceed — the interface change in Step 3 is still required for the command to read it generically.

- [ ] **Step 3: Add optional `filenamePrefix` to the interface**

```ts
// src/renderers/AuditRenderer.ts
import type { AuditResult } from '../findings/AuditResult.js';

export interface AuditRenderer {
  readonly format: string;
  readonly fileExtension: string;
  readonly filenamePrefix?: string;   // when set, used instead of 'sf-audit' for the output filename
  render(result: AuditResult): string;
}
```

- [ ] **Step 4: Add flags + runtime construction in the command**

In `src/commands/audit/security.ts`:

(a) Add imports near the top:
```ts
import { ClientReportRenderer } from '../../renderers/ClientReportRenderer.js';
import { resolveBranding, type BrandingOverrides } from '../../report/branding.js';
import { readFileSync } from 'node:fs';
```

(b) Add flags inside `public static flags = { ... }`:
```ts
    'prepared-for': Flags.string({ summary: 'Client name for the executive report cover line.' }),
    branding: Flags.string({ summary: 'Path to a report-branding.json to override CloudCounsel defaults.', helpValue: './report-branding.json' }),
    top: Flags.integer({ summary: 'Number of executive priorities to highlight.', default: 5 }),
```

(c) Replace the renderer loop. Find:
```ts
    const formats = flags.format.split(',').map((f) => f.trim());
    fs.mkdirSync(flags.output, { recursive: true });
    for (const format of formats) {
      const renderer = RENDERERS[format];
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, md, json`);
        continue;
      }
      const output = renderer.render(result);
      const filename = `sf-audit-${orgInfo.id}-${Date.now()}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, output, 'utf-8');
      this.log(`\nReport written: ${outputPath}`);
    }
```
with:
```ts
    const formats = flags.format.split(',').map((f) => f.trim());
    fs.mkdirSync(flags.output, { recursive: true });
    for (const format of formats) {
      const renderer = this.rendererFor(format, flags);
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, md, json, executive`);
        continue;
      }
      const output = renderer.render(result);
      const prefix = renderer.filenamePrefix ?? 'sf-audit';
      const filename = `${prefix}-${orgInfo.id}-${Date.now()}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, output, 'utf-8');
      this.log(`\nReport written: ${outputPath}`);
    }
```

(d) Add a private method on the class:
```ts
  private rendererFor(format: string, flags: { 'prepared-for'?: string; branding?: string; top: number }): AuditRenderer | undefined {
    if (format === 'executive') {
      let overrides: BrandingOverrides | undefined;
      if (flags.branding) overrides = JSON.parse(readFileSync(flags.branding, 'utf-8')) as BrandingOverrides;
      const branding = resolveBranding(overrides, flags['prepared-for']);
      return new ClientReportRenderer({ branding, topN: flags.top });
    }
    return RENDERERS[format];
  }
```
Ensure `AuditRenderer` is imported as a type in this file (add `import type { AuditRenderer } from '../../renderers/AuditRenderer.js';` if not present).

- [ ] **Step 5: Build and run the full suite**

Run: `npm run build && npm test`
Expected: build clean; all suites green including the new renderer/report suites.

- [ ] **Step 6: Smoke-render manually (no org needed)**

Run:
```bash
node --input-type=module -e "
import { ClientReportRenderer } from './lib/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from './lib/report/branding.js';
import { writeFileSync } from 'node:fs';
const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5 });
const res = { generatedAt:new Date(), orgId:'00D', orgName:'Demo', orgType:'Production', isSandbox:false, instance:'NA', instanceUrl:'x', healthScore:62, grade:'C', metrics:{}, findings:[{id:'f1',checkId:'internal-user-mfa',category:'Auth',riskLevel:'CRITICAL',title:'3 admins without MFA',detail:'d',remediation:'Enforce MFA'}], attackChains:[] };
writeFileSync('/tmp/exec-report.html', r.render(res));
console.log('wrote /tmp/exec-report.html');
"
```
Expected: writes `/tmp/exec-report.html`; open it to eyeball the brand/layout (print to PDF to sanity-check).

- [ ] **Step 7: Commit**

```bash
git add src/renderers/AuditRenderer.ts src/commands/audit/security.ts test/unit/renderers/AuditRenderer-prefix.test.ts
git commit -m "feat(audit): wire --format executive with branding/prepared-for/top flags"
```

---

### Task 8: Update README + CLAUDE.md for the executive format

**Files:**
- Modify: `README.md` (Options table + a short "Executive report" subsection)
- Modify: `CLAUDE.md` (note the new renderer + report modules)

- [ ] **Step 1: README — document the format**

In the `--format` row of the Options table, change the description to include `executive`. Add after the Examples block:

```markdown
### Executive report

`--format executive` produces a CloudCounsel-branded, print-to-PDF HTML report for clients:
grade, executive summary, top priorities with abuse/impact narratives, attack scenarios, and a
risk×effort remediation roadmap. Open it and "Save as PDF".

```bash
sf audit security --target-org myOrg --format executive --prepared-for "Acme Health" --top 5
# white-label / co-brand:
sf audit security --target-org myOrg --format executive --branding ./report-branding.json
```
```

- [ ] **Step 2: CLAUDE.md — note the modules**

Under the Map section, add a bullet:
```markdown
- `src/renderers/ClientReportRenderer.ts` + `src/report/` (branding, fonts, ExecutivePriorities, RemediationRoadmap) — the `--format executive` client report. Compliance matrix deferred (gated on control verification).
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document the --format executive report"
```

---

## Self-Review

**Spec coverage (sections 1–5, 7–8):**
- §2 output mechanism (self-contained print HTML, embedded fonts, new `--format`) → Tasks 3, 6, 7.
- §3 sections: cover+grade (Task 6 cover), exec summary (Task 6 summary), top-N priorities w/ impact+chain note (Tasks 4, 6), attack scenarios (Task 6 scenarios), roadmap (Tasks 5, 6), full findings (Task 6 appendix), scope footer (Task 6 footer). §6 compliance matrix — **deferred to next plan** (gated on verification), noted in scope.
- §5 branding defaults + overrides + font token → Task 2; embedded fonts → Task 3.
- §4 CheckMeta effort/impact → consumed in Tasks 5, 6 (already built in prior plan).
- Invocation/flags + filename distinguisher → Task 7.

**Placeholder scan:** No TODO/TBD. All steps include complete code. HTML is concise but complete and renders.

**Type consistency:** `Branding`/`DEFAULT_BRANDING`/`resolveBranding`/`BrandingOverrides` (Task 2) used identically in Tasks 6, 7. `fontFaceCss` (Task 3) used in Task 6. `selectPriorities(findings, chainFindingIds, topN)` (Task 4) and `buildRoadmap(findings)`→`Roadmap{quick,moderate,project}` (Task 5) used with matching signatures in Task 6. `ClientReportOptions{branding,topN}` consistent Tasks 6–7. `filenamePrefix` added to `AuditRenderer` (Task 7) matches the class property (Task 6). `getCheckMeta` from existing `CheckMeta.ts`. `AttackChain` fields (`title`,`severity`,`narrative`,`remediation`,`steps[].findingId`) match `src/chains/AttackChain.ts`.

**Deferred (correctly out of scope):** compliance matrix section + `--frameworks` flag (Plan 3, after verification). Noted in header and §3.
