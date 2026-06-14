# Executive Compliance Report — Design

**Date:** 2026-06-14
**Status:** Approved for planning
**Component:** `@cclabsnz/sf-audit` plugin — new `executive` report renderer + sourced compliance catalog

## 1. Purpose

Turn a raw audit into an **auditor-ready, CloudCounsel-branded client deliverable**: a print-optimised report that leads with the few things that matter, explains *how each weakness gets abused and what incident it causes*, gives a prioritised remediation roadmap, and maps findings to **exact, cited framework requirements**.

This is the artifact a CISO reads and forwards internally — the consulting upsell hook and the differentiator a generic Salesforce scanner cannot produce (NZ framework coverage; sourced control text).

Non-goals (this spec): true in-CLI PDF generation, trend/diff inside the executive report (covered by `sf audit diff`), multi-org rollups, hosted/continuous monitoring.

## 2. Output mechanism

A new `AuditRenderer` that emits a **self-contained, print-optimised branded HTML file**. The user opens it and "Save as PDF" (or headless-prints in CI). Chosen over bundling a headless browser (≈300 MB Chromium in a published npm CLI; conflicts with disk-hygiene rules) or a JS PDF lib (manual layout, hard to brand).

- Self-contained: DM Sans + DM Serif Display woff2 and any logo are **base64-embedded** (~110 KB) so the file is offline and prints identically anywhere.
- Print CSS: `@page` margins, page-break control between sections, screen + print stylesheets in one document.
- The HTML doubles as a shareable artifact in its own right.

### Invocation

New `--format` value `executive`, combinable with existing formats:

```
sf audit security --target-org acme --format executive \
  --prepared-for "Acme Health" \            # co-brand line (optional)
  --branding ./report-branding.json \        # white-label overrides (optional)
  --frameworks universal|nz|all|<list> \     # compliance scope (default: universal)
  --top 5                                     # exec-priorities cap (default 5)
```

`html` remains the full technical report; `executive` is the client-facing deliverable. Output file: `SF_Audit_Executive_<org>_<timestamp>.html`. Because both `html` and `executive` share the `.html` extension, the command must distinguish output filenames per renderer (e.g. an optional `filenamePrefix`/`reportKind` on the renderer, or branch in the command) so running `--format html,executive` writes two non-colliding files.

## 3. Report structure (sections, in order)

1. **Cover** — CloudCounsel brand, org name + id, date, large **grade badge (A–F)**, "Prepared by CloudCounsel Limited for *<Client>*".
2. **Executive Summary** — grade + health score, one-paragraph posture statement, severity counts (CRITICAL→INFO + inconclusive), pointer to Scope & Limitations.
3. **Executive Priorities (Top N, default 5)** — the focus. Each item: title · severity · **how it's abused / likely incident** · the fix · **effort tier** · cited framework refs. Caps the noise when an org has many findings.
4. **Attack Scenarios** — named **attack chains** from `src/chains/`: multi-step "this is how you actually get breached" narratives correlating findings.
5. **Remediation Roadmap** — grouped **Quick wins (≤1 day) / Moderate (days) / Projects (weeks)**, risk-sorted within each tier.
6. **Compliance Coverage Matrix** — per selected framework: control id · **exact requirement text** · status (satisfied / findings hit / inconclusive) · linked finding(s). Version-pinned and cited.
7. **Full Findings** (appendix) — every finding by category with detail/remediation/tags; inconclusive flagged distinctly.
8. **Scope & Liability footer** — the existing disclaimer (read-only, point-in-time, not a pen test, no warranty) + the compliance-mapping basis line (frameworks + versions).

## 4. Finding metadata: `CheckMeta`

Mirrors the existing central-map pattern (`ComplianceMapping`) — **one file keyed by `checkId`, not 61 edits.**

`src/findings/CheckMeta.ts`:

```ts
export interface CheckMeta {
  effort: 'quick' | 'moderate' | 'project';   // drives roadmap tiers (≤1d / days / weeks)
  impact: string;                              // standalone abuse/incident line for top-N items
}
export const CHECK_META: Record<string, CheckMeta> = {
  'guest-executable-apex': {
    effort: 'project',
    impact: 'Unauthenticated web users can execute Apex that bypasses sharing — bulk record exfiltration without login.',
  },
  'internal-user-mfa': {
    effort: 'quick',
    impact: 'A stolen or guessed admin password grants full org access with no second factor to stop it.',
  },
  // …one entry per registered check
};
```

- `effort` → roadmap grouping.
- `impact` → the abuse/incident narrative for a **standalone** top-N finding. Where a finding participates in an attack chain, the **chain narrative takes the lead** and `impact` is the fallback.
- **Guard:** a unit test asserts every registered `checkId` has a `CHECK_META` entry (same completeness pattern as the registry), so it can't drift as checks are added.

## 5. Sourced compliance — making callouts bulletproof

The current model (`checkId → ['ISO-A.9.2', …]` bare tags) is **not defensible** in a signed deliverable: a tag has no source, no requirement text, no proof. Replace it with a sourced catalog + thin mapping + enforcement guards.

### 5.1 Control Catalog (authoritative, cited)

One catalog module per framework under `src/compliance/catalogs/` (e.g. `iso27001.ts`, `soc2.ts`, `owasp.ts`, `hiso10029.ts`, `privacyAct.ts`, `nzism.ts`). Each control is fully specified:

```ts
export interface ControlDef {
  id: string;            // exact identifier, e.g. 'NZISM-16.1.35'
  framework: Framework;  // 'OWASP' | 'SOC2' | 'ISO27001' | 'HISO10029' | 'PRIVACY_ACT' | 'NZISM' | 'HIPAA' | 'GDPR'
  version: string;       // exact standard version mapped, e.g. 'v3.7 (Dec 2024)'
  title: string;
  requirement: string;   // faithful requirement text / close paraphrase
  sourceRef: string;     // citation, e.g. 'NZISM v3.7, §16.1.35'
  url?: string;          // optional link to the clause
  verified: boolean;     // provenance gate — see 5.3
}
```

Each `Framework` catalog also declares its pinned `version` once, surfaced in the report footer.

### 5.2 Mapping stays thin

`src/compliance/mapping.ts`: `checkId → controlId[]`. Replaces `COMPLIANCE_MAP`. Every id must resolve to a catalogued control. The report renders the **resolved requirement text + citation**, never a bare code.

### 5.3 Three enforcement guards (unit tests / CI)

1. **Referential integrity** — every `controlId` in the mapping must exist in some catalog. Fails the build on a dangling/typo'd ref. (Same guard family as the registry/CheckMeta completeness tests.)
2. **Provenance gate** — the renderer **excludes any control whose `verified === false`** from the rendered matrix, and a test asserts that any control referenced by a *selected default framework* is verified. Effect: **nothing ships as "compliant-to-clause" on un-cross-checked data.** I author catalog drafts with `verified: false`; a human flips to `true` only after checking the clause against the source document. If a user selects a framework pack that is not yet fully verified (e.g. `nz` before NZISM sign-off), the matrix renders the verified controls and shows an explicit **"N controls pending source verification — excluded"** notice rather than silently omitting them, so the gap is visible, not hidden.
3. **Version pinning** — each framework declares its exact version; the report footer prints *"Mapped against ISO/IEC 27001:2022, SOC 2 (2017 TSC), HISO 10029:2022, NZ Privacy Act 2020, NZISM v3.7"* so the basis is explicit and dated.

### 5.4 Verification worksheet (deliverable alongside the catalogs)

`docs/compliance/verification-worksheet.md` — a generated table of every catalog control (`id · framework · sourceRef · verified?`) for the human sign-off pass. Authoring drafts ship `verified: false`; the worksheet tracks the cross-check so the verified state is auditable, not implicit.

## 6. Framework packs and selection

`--frameworks` resolves named packs or an explicit list:

| Pack | Frameworks | Default? |
|---|---|---|
| `universal` | OWASP, SOC 2, ISO 27001 | **yes** |
| `nz` | ISO 27001, HISO 10029, NZ Privacy Act (IPP 5/12) | — |
| `all` | universal + nz + HIPAA + GDPR | — |
| explicit | e.g. `owasp,iso,hiso,nzism` | — |

- **Universal core** (OWASP/SOC2/ISO) ships first — already mapped, just migrated into the catalog model.
- **NZ pack:** HISO 10029 (cheap — ISO 27002 crosswalk) and NZ Privacy Act (IPP 5 security rollup, IPP 12 cross-border) authored now. **NZISM** is the real authoring effort and lands as a fast-follow once its control crosswalk is built and verified.
- **HIPAA/GDPR** remain opt-in (jurisdiction-specific; irrelevant or misleading for most NZ clients).
- Rationale: showing frameworks that don't apply reads as generic tooling and creates liability; relevance beats breadth for a paid deliverable.

## 7. Branding

Configurable theme; **default = the live CloudCounsel brand** (extracted from the website design handoff).

Defaults: cream `#faf6ef` / `#f7f7f2` backgrounds · ink `#1a1d24` · blue accent `#3a5a82` / deep `#2c4768` · muted text `#636770` · borders `#e9e9e3` · severity from the brand palette (red `#7d3a3a`, amber, green `#4a7d5e`) · DM Serif Display (display) + DM Sans (body).

`report-branding.json` overrides (all optional; omit file = CloudCounsel default):

```jsonc
{
  "firmName":    "CloudCounsel Limited",
  "primary":     "#3a5a82",
  "fontDisplay": "DM Serif Display",   // brand-refresh = one-line change
  "fontBody":    "DM Sans",
  "logoPath":    "./cc-logo.svg",      // optional; embedded base64
  "contact":     "hello@cloudcounsel.co.nz",
  "preparedFor": "Acme Health"         // also settable via --prepared-for
}
```

Font family is an overridable token so a future brand-identity refresh (the DM fonts are on the generic "reflex-reject" list; revisiting them is a separate exercise) needs no renderer changes — swap the token, drop in the new woff2.

## 8. Components (small, testable units)

| Unit | Responsibility | Depends on |
|---|---|---|
| `src/findings/CheckMeta.ts` | effort + impact per check | check ids |
| `src/compliance/catalogs/*.ts` | sourced control definitions per framework | — |
| `src/compliance/mapping.ts` | `checkId → controlId[]` (replaces `COMPLIANCE_MAP`) | catalogs |
| `src/compliance/resolve.ts` | resolve a finding → verified `ControlDef[]`; apply framework selection + provenance gate | catalogs, mapping |
| `src/report/ExecutivePriorities.ts` | select top N (risk, weighted by chain membership) | result, chains |
| `src/report/RemediationRoadmap.ts` | group findings by effort tier | result, CheckMeta |
| `src/report/ComplianceMatrix.ts` | invert mapping → framework→control→status/findings | resolve |
| `src/report/branding.ts` | merge `report-branding.json` over defaults; base64-embed fonts/logo | assets |
| `src/renderers/ClientReportRenderer.ts` | assemble the 8 sections into self-contained HTML (reuses existing escaping helpers) | all of the above |

**Wiring:** `ClientReportRenderer` needs per-run options (branding, frameworks, topN, preparedFor), so `security.ts` constructs it at runtime from parsed flags when `executive` is in `--format`, rather than from the static `RENDERERS` map. Other renderers are unchanged. New flags: `--prepared-for`, `--branding`, `--frameworks`, `--top`.

**Compliance migration:** existing checks' `ComplianceMapping` tags are migrated into the catalog model. The current `ComplianceMapping.ts` is replaced by `compliance/mapping.ts` + catalogs; `CheckEngine`'s tag-population step is updated to resolve via the new module. Existing renderers that display `complianceTags` keep working (resolve to the same id strings).

**Assets:** bundle the 4 needed woff2 (DM Sans normal/italic, DM Serif Display normal/italic — latin) into `src/assets/fonts/` and add to `package.json` `files`.

## 9. Testing

- `CheckMeta` completeness — every registered checkId has an entry.
- Compliance referential integrity — every mapped controlId exists in a catalog.
- Provenance gate — controls referenced by default frameworks are `verified`; unverified controls are excluded from render.
- `ExecutivePriorities` — selection/order (risk + chain weighting, cap at N).
- `RemediationRoadmap` — correct tier grouping and within-tier risk sort.
- `ComplianceMatrix` — inversion correctness; framework selection filters correctly.
- `branding` — override-merge precedence; defaults applied when file absent.
- `ClientReportRenderer` — structural render test: all 8 sections present, output is self-contained (no external refs), HTML-escaping holds, footer cites pinned versions.

Mirrors existing renderer/test style (mocked inputs; `node --experimental-vm-modules` jest). Done = `npm run build` clean and `npm test` green with new suites.

## 10. Phasing

1. **Catalog + mapping model** (universal core migrated from existing tags) + guards + tests. No user-visible change yet.
2. **`CheckMeta`** (effort + impact) authored for all checks + completeness guard.
3. **`executive` renderer** + sections 1–5, 7–8 (priorities, attack scenarios, roadmap, findings, scope) + branding + flags.
4. **Compliance matrix** (section 6) wired to selected frameworks; universal pack live.
5. **NZ pack** — HISO + Privacy Act catalogs authored (`verified: false`) + verification worksheet; `--frameworks nz`.
6. **NZISM** fast-follow once crosswalk authored and verified.

Each phase builds clean and keeps tests green independently.
