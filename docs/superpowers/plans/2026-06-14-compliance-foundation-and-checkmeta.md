# Compliance Foundation + CheckMeta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat `ComplianceMapping` tag list with a sourced, version-pinned, verification-gated control catalog, and add per-check `effort`/`impact` metadata — the data foundation the executive report renders.

**Architecture:** A per-framework catalog of fully-specified `ControlDef`s (id, version, requirement text, sourceRef, `verified`), a thin `checkId → controlId[]` mapping, and a `resolve` module that filters by framework pack and a provenance gate. Three unit-test guards enforce referential integrity, completeness, and provenance. `CheckEngine` is migrated to the new module; existing renderers keep working because `complianceTags` still resolves to the same id strings. `CheckMeta` mirrors the same central-map pattern.

**Tech Stack:** TypeScript ESM (NodeNext — relative imports end in `.js`), Jest (`node --experimental-vm-modules`, run via `npm test`). pnpm for deps.

**Scope:** This plan is spec phases 1–2 only (`docs/superpowers/specs/2026-06-14-executive-compliance-report-design.md`). The `executive` renderer + matrix (phases 3–4) and NZ pack (phases 5–6) are separate plans. No user-visible behaviour changes here; the audit still runs and existing reports are unchanged.

**Catalog content note:** Control definitions are authored as **drafts with `verified: false`**. Exact requirement wording and clause numbers are confirmed against source standards in a later human verification pass (per the spec's provenance gate). Each content task gives the exact id inventory (extracted from the current code), the source standard, and worked examples to copy the shape from.

---

### Task 1: Compliance core types + catalog lookup

**Files:**
- Create: `src/compliance/types.ts`
- Create: `src/compliance/catalogs/index.ts`
- Test: `test/unit/compliance/catalog.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/compliance/catalog.test.ts
import { getControl, ALL_CONTROLS } from '../../../src/compliance/catalogs/index.js';

describe('catalog lookup', () => {
  it('returns a control by id', () => {
    const c = getControl('OWASP-A01');
    expect(c).toBeDefined();
    expect(c?.framework).toBe('OWASP');
    expect(typeof c?.requirement).toBe('string');
    expect(c?.requirement.length).toBeGreaterThan(0);
  });

  it('returns undefined for an unknown id', () => {
    expect(getControl('NOPE-999')).toBeUndefined();
  });

  it('has no duplicate control ids across catalogs', () => {
    const ids = ALL_CONTROLS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/compliance/catalog.test.ts`
Expected: FAIL — cannot find module `src/compliance/catalogs/index.js`.

- [ ] **Step 3: Write the types**

```ts
// src/compliance/types.ts
export type Framework =
  | 'OWASP' | 'SOC2' | 'ISO27001' | 'SBS'
  | 'HISO10029' | 'PRIVACY_ACT' | 'NZISM' | 'HIPAA' | 'GDPR';

export interface ControlDef {
  id: string;            // exact identifier, e.g. 'NZISM-16.1.35'
  framework: Framework;
  version: string;       // exact standard version mapped, e.g. 'ISO/IEC 27001:2022'
  title: string;
  requirement: string;   // faithful requirement text / close paraphrase
  sourceRef: string;     // citation, e.g. 'ISO/IEC 27001:2022, A.9.2'
  url?: string;
  verified: boolean;     // provenance gate — drafts are false until human-checked
}

export type FrameworkPack = 'universal' | 'nz' | 'all';
```

- [ ] **Step 4: Write the catalog index with a single seed control**

```ts
// src/compliance/catalogs/index.ts
import type { ControlDef } from '../types.js';
import { OWASP_CONTROLS } from './owasp.js';

export const ALL_CONTROLS: ControlDef[] = [
  ...OWASP_CONTROLS,
];

const BY_ID: Map<string, ControlDef> = new Map(ALL_CONTROLS.map((c) => [c.id, c]));

export function getControl(id: string): ControlDef | undefined {
  return BY_ID.get(id);
}
```

- [ ] **Step 5: Create the OWASP catalog (full universal framework — 7 controls)**

```ts
// src/compliance/catalogs/owasp.ts
import type { ControlDef } from '../types.js';

const V = 'OWASP Top 10:2021';

export const OWASP_CONTROLS: ControlDef[] = [
  { id: 'OWASP-A01', framework: 'OWASP', version: V, title: 'Broken Access Control',
    requirement: 'Access control enforces policy so users cannot act outside their intended permissions; deny by default, enforce record/field ownership.',
    sourceRef: 'OWASP Top 10:2021 A01', verified: false },
  { id: 'OWASP-A02', framework: 'OWASP', version: V, title: 'Cryptographic Failures',
    requirement: 'Sensitive data (credentials, secrets, PII) is protected in transit and at rest; secrets are not hardcoded or exposed.',
    sourceRef: 'OWASP Top 10:2021 A02', verified: false },
  { id: 'OWASP-A03', framework: 'OWASP', version: V, title: 'Injection',
    requirement: 'Untrusted input is validated/escaped so it cannot alter queries, markup, or commands (SOQL injection, XSS).',
    sourceRef: 'OWASP Top 10:2021 A03', verified: false },
  { id: 'OWASP-A05', framework: 'OWASP', version: V, title: 'Security Misconfiguration',
    requirement: 'Platform and application security settings are hardened and reviewed; unnecessary features and exposure are removed.',
    sourceRef: 'OWASP Top 10:2021 A05', verified: false },
  { id: 'OWASP-A06', framework: 'OWASP', version: V, title: 'Vulnerable and Outdated Components',
    requirement: 'Installed packages and platform components are inventoried and kept current; outdated/unsupported components are flagged.',
    sourceRef: 'OWASP Top 10:2021 A06', verified: false },
  { id: 'OWASP-A07', framework: 'OWASP', version: V, title: 'Identification and Authentication Failures',
    requirement: 'Authentication is strong (MFA, session controls, IP/login policy) and resistant to credential stuffing and session abuse.',
    sourceRef: 'OWASP Top 10:2021 A07', verified: false },
  { id: 'OWASP-A09', framework: 'OWASP', version: V, title: 'Security Logging and Monitoring Failures',
    requirement: 'Security-relevant events are logged, retained, and monitored so incidents can be detected and investigated.',
    sourceRef: 'OWASP Top 10:2021 A09', verified: false },
];
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npm test -- test/unit/compliance/catalog.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add src/compliance/types.ts src/compliance/catalogs/index.ts src/compliance/catalogs/owasp.ts test/unit/compliance/catalog.test.ts
git commit -m "feat(compliance): control catalog model + OWASP catalog"
```

---

### Task 2: Author the remaining universal catalogs (SOC2, ISO 27001) + SBS

**Files:**
- Create: `src/compliance/catalogs/soc2.ts`
- Create: `src/compliance/catalogs/iso27001.ts`
- Create: `src/compliance/catalogs/sbs.ts`
- Modify: `src/compliance/catalogs/index.ts`
- Test: `test/unit/compliance/catalog.test.ts` (extend)

**Exact id inventory to author** (extracted from `src/findings/ComplianceMapping.ts`):
- SOC2 (11): `CC6.1 CC6.2 CC6.3 CC6.4 CC6.6 CC6.7 CC7.1 CC7.2 CC8.1 CC9.1 CC9.2` (version `SOC 2 (2017 TSC)`, sourceRef `SOC 2 (2017 TSC), <CC>`)
- ISO27001 (10): `A.8.2 A.9.2 A.9.4 A.10.1 A.12.1 A.12.4 A.12.6 A.13.2 A.14.1 A.14.2` (version `ISO/IEC 27001:2022`, sourceRef `ISO/IEC 27001:2022, Annex <A.x>`)
- SBS: every distinct `SBS-*` id in `ComplianceMapping.ts` (version `Salesforce Security Baseline`, sourceRef `Salesforce Security Baseline, <id>`). Extract with: `grep -rhoE "'SBS-[A-Za-z0-9-]+'" src/findings/ComplianceMapping.ts | tr -d "'" | sort -u`

All entries `verified: false`. Worked example for SOC2 (copy this shape for every id):

```ts
// src/compliance/catalogs/soc2.ts
import type { ControlDef } from '../types.js';
const V = 'SOC 2 (2017 TSC)';
export const SOC2_CONTROLS: ControlDef[] = [
  { id: 'SOC2-CC6.1', framework: 'SOC2', version: V, title: 'Logical access controls',
    requirement: 'The entity implements logical access security measures to protect against unauthorized access to information assets.',
    sourceRef: 'SOC 2 (2017 TSC), CC6.1', verified: false },
  // … CC6.2, CC6.3, CC6.4, CC6.6, CC6.7, CC7.1, CC7.2, CC8.1, CC9.1, CC9.2
];
```

Worked example for ISO 27001 (Annex A 2022 titles):

```ts
// src/compliance/catalogs/iso27001.ts
import type { ControlDef } from '../types.js';
const V = 'ISO/IEC 27001:2022';
export const ISO27001_CONTROLS: ControlDef[] = [
  { id: 'ISO-A.9.2', framework: 'ISO27001', version: V, title: 'User access management',
    requirement: 'Formal user access provisioning and de-provisioning controls restrict access to authorized users.',
    sourceRef: 'ISO/IEC 27001:2022, A.9.2', verified: false },
  // … A.8.2, A.9.4, A.10.1, A.12.1, A.12.4, A.12.6, A.13.2, A.14.1, A.14.2
];
```

- [ ] **Step 1: Extend the failing test**

Add to `test/unit/compliance/catalog.test.ts`:

```ts
import { ALL_CONTROLS } from '../../../src/compliance/catalogs/index.js';

it('contains the universal frameworks', () => {
  const frameworks = new Set(ALL_CONTROLS.map((c) => c.framework));
  for (const fw of ['OWASP', 'SOC2', 'ISO27001', 'SBS']) {
    expect(frameworks.has(fw as never)).toBe(true);
  }
});

it('every control has the required shape', () => {
  for (const c of ALL_CONTROLS) {
    expect(c.id).toMatch(/.+/);
    expect(c.title).toMatch(/.+/);
    expect(c.requirement.length).toBeGreaterThan(10);
    expect(c.sourceRef).toMatch(/.+/);
    expect(c.version).toMatch(/.+/);
    expect(typeof c.verified).toBe('boolean');
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/compliance/catalog.test.ts`
Expected: FAIL — `SOC2`/`ISO27001`/`SBS` frameworks not present.

- [ ] **Step 3: Author the three catalog files**

Create `soc2.ts`, `iso27001.ts`, `sbs.ts` per the inventories and worked examples above — one `ControlDef` per id, all `verified: false`.

- [ ] **Step 4: Wire them into the index**

```ts
// src/compliance/catalogs/index.ts — update imports + spread
import { OWASP_CONTROLS } from './owasp.js';
import { SOC2_CONTROLS } from './soc2.js';
import { ISO27001_CONTROLS } from './iso27001.js';
import { SBS_CONTROLS } from './sbs.js';

export const ALL_CONTROLS: ControlDef[] = [
  ...OWASP_CONTROLS, ...SOC2_CONTROLS, ...ISO27001_CONTROLS, ...SBS_CONTROLS,
];
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npm test -- test/unit/compliance/catalog.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/compliance/catalogs/ test/unit/compliance/catalog.test.ts
git commit -m "feat(compliance): SOC2, ISO 27001, and SBS catalogs (draft, unverified)"
```

---

### Task 3: Check→control mapping + referential-integrity guard

**Files:**
- Create: `src/compliance/mapping.ts`
- Test: `test/unit/compliance/referentialIntegrity.test.ts`

The mapping is a **verbatim migration** of `COMPLIANCE_MAP` from `src/findings/ComplianceMapping.ts` (same keys, same id arrays), renamed. HIPAA/GDPR/NZ ids are **dropped for now** (their catalogs land in later plans); only ids with a catalog entry remain, so referential integrity holds. Keep OWASP/SOC2/ISO/SBS ids.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/compliance/referentialIntegrity.test.ts
import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
import { getControl } from '../../../src/compliance/catalogs/index.js';

it('every mapped control id exists in a catalog', () => {
  const dangling: string[] = [];
  for (const ids of Object.values(CHECK_CONTROL_MAP)) {
    for (const id of ids) if (!getControl(id)) dangling.push(id);
  }
  expect(dangling).toEqual([]);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/compliance/referentialIntegrity.test.ts`
Expected: FAIL — cannot find module `mapping.js`.

- [ ] **Step 3: Write the mapping**

Create `src/compliance/mapping.ts` by copying every entry from `COMPLIANCE_MAP`, keeping only `OWASP-*`, `SOC2-*`, `ISO-*`, `SBS-*` ids per entry:

```ts
// src/compliance/mapping.ts
export const CHECK_CONTROL_MAP: Record<string, string[]> = {
  'users-and-admins': ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.2', 'SBS-ACS-004'],
  'permissions':      ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.2', 'SBS-ACS-002', 'SBS-ACS-005'],
  // … one entry per checkId, HIPAA-*/GDPR-* removed
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/compliance/referentialIntegrity.test.ts`
Expected: PASS — no dangling ids.

- [ ] **Step 5: Commit**

```bash
git add src/compliance/mapping.ts test/unit/compliance/referentialIntegrity.test.ts
git commit -m "feat(compliance): check→control mapping + referential-integrity guard"
```

---

### Task 4: Resolve module — framework packs + provenance gate

**Files:**
- Create: `src/compliance/resolve.ts`
- Test: `test/unit/compliance/resolve.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/compliance/resolve.test.ts
import { resolveControls, packFrameworks, getComplianceTags } from '../../../src/compliance/resolve.js';

describe('resolveControls', () => {
  it('returns only controls in the selected frameworks', () => {
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: false });
    expect(out.every((c) => c.framework === 'ISO27001')).toBe(true);
  });

  it('excludes unverified controls when requireVerified is true', () => {
    // catalogs ship verified:false, so a verified-only resolve is empty for now
    const out = resolveControls('users-and-admins', { frameworks: ['ISO27001'], requireVerified: true });
    expect(out).toEqual([]);
  });

  it('packFrameworks maps universal to OWASP/SOC2/ISO', () => {
    expect(packFrameworks('universal').sort()).toEqual(['ISO27001', 'OWASP', 'SOC2']);
  });
});

describe('getComplianceTags (compat shim)', () => {
  it('returns the raw id strings for a check, unchanged from the old behaviour', () => {
    const tags = getComplianceTags('users-and-admins');
    expect(tags).toContain('OWASP-A01');
    expect(tags).toContain('ISO-A.9.2');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/compliance/resolve.test.ts`
Expected: FAIL — cannot find module `resolve.js`.

- [ ] **Step 3: Write the resolve module**

```ts
// src/compliance/resolve.ts
import type { ControlDef, Framework, FrameworkPack } from './types.js';
import { CHECK_CONTROL_MAP } from './mapping.js';
import { getControl } from './catalogs/index.js';

const PACKS: Record<FrameworkPack, Framework[]> = {
  universal: ['OWASP', 'SOC2', 'ISO27001'],
  nz: ['ISO27001', 'HISO10029', 'PRIVACY_ACT'],
  all: ['OWASP', 'SOC2', 'ISO27001', 'SBS', 'HISO10029', 'PRIVACY_ACT', 'NZISM', 'HIPAA', 'GDPR'],
};

export function packFrameworks(pack: FrameworkPack): Framework[] {
  return PACKS[pack];
}

export interface ResolveOptions {
  frameworks?: Framework[];        // when omitted, all frameworks the check maps to
  requireVerified?: boolean;       // default true
}

export function resolveControls(checkId: string, opts: ResolveOptions = {}): ControlDef[] {
  const requireVerified = opts.requireVerified ?? true;
  const ids = CHECK_CONTROL_MAP[checkId] ?? [];
  const out: ControlDef[] = [];
  for (const id of ids) {
    const c = getControl(id);
    if (!c) continue;
    if (opts.frameworks && !opts.frameworks.includes(c.framework)) continue;
    if (requireVerified && !c.verified) continue;
    out.push(c);
  }
  return out;
}

/** Backward-compatible: the bare id strings, as the old ComplianceMapping returned. */
export function getComplianceTags(checkId: string): string[] {
  return CHECK_CONTROL_MAP[checkId] ?? [];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/compliance/resolve.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/compliance/resolve.ts test/unit/compliance/resolve.test.ts
git commit -m "feat(compliance): resolve module with framework packs + provenance gate"
```

---

### Task 5: Migrate CheckEngine to the new module; remove old ComplianceMapping

**Files:**
- Modify: `src/checks/CheckEngine.ts:9` (import) and line ~74 (usage)
- Delete: `src/findings/ComplianceMapping.ts`
- Modify: any other importer of `ComplianceMapping.js` (find first)

- [ ] **Step 1: Find all importers of the old module**

Run: `grep -rn "findings/ComplianceMapping" src test`
Expected: a list (at least `src/checks/CheckEngine.ts`). Note each.

- [ ] **Step 2: Repoint CheckEngine's import**

In `src/checks/CheckEngine.ts`, change line 9 from:

```ts
import { getComplianceTags } from '../findings/ComplianceMapping.js';
```

to:

```ts
import { getComplianceTags } from '../compliance/resolve.js';
```

The call site (`const tags = getComplianceTags(check.id)` → `complianceTags: tags`) is unchanged — same signature, same return.

- [ ] **Step 3: Repoint any other importers**

For each file from Step 1 other than CheckEngine, change the import path to `../compliance/resolve.js` (adjust `../` depth per file location). If a test imported `COMPLIANCE_MAP` directly, repoint it to `CHECK_CONTROL_MAP` from `../compliance/mapping.js`.

- [ ] **Step 4: Delete the old module**

Run: `git rm src/findings/ComplianceMapping.ts`

- [ ] **Step 5: Build and run the FULL suite**

Run: `npm run build && npm test`
Expected: build clean; all suites pass (the 25 existing + the 3 new compliance suites). Findings still carry the same `complianceTags` id strings, so renderer snapshot/assertion tests are unaffected.

- [ ] **Step 6: Commit**

```bash
git add -A src test
git commit -m "refactor(compliance): migrate CheckEngine to resolve module; remove ComplianceMapping"
```

---

### Task 6: Mapping completeness guard

**Files:**
- Test: `test/unit/compliance/completeness.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/compliance/completeness.test.ts
import { CHECKS } from '../../../src/checks/registry.js';
import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';

it('every registered check has at least one mapped control', () => {
  const missing = CHECKS.map((c) => c.id).filter((id) => !(CHECK_CONTROL_MAP[id]?.length));
  expect(missing).toEqual([]);
});
```

- [ ] **Step 2: Run test**

Run: `npm test -- test/unit/compliance/completeness.test.ts`
Expected: PASS if every check is mapped; if it FAILS, it lists the unmapped check ids — add an entry for each to `src/compliance/mapping.ts` (pick the relevant existing framework controls), then re-run until green.

- [ ] **Step 3: Commit**

```bash
git add src/compliance/mapping.ts test/unit/compliance/completeness.test.ts
git commit -m "test(compliance): mapping completeness guard for all registered checks"
```

---

### Task 7: CheckMeta — effort + impact

**Files:**
- Create: `src/findings/CheckMeta.ts`
- Test: `test/unit/findings/CheckMeta.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/findings/CheckMeta.test.ts
import { getCheckMeta, CHECK_META } from '../../../src/findings/CheckMeta.js';

describe('CheckMeta', () => {
  it('returns effort and impact for a known check', () => {
    const m = getCheckMeta('internal-user-mfa');
    expect(m).toBeDefined();
    expect(['quick', 'moderate', 'project']).toContain(m?.effort);
    expect((m?.impact.length ?? 0)).toBeGreaterThan(10);
  });

  it('every effort value is a valid tier', () => {
    for (const m of Object.values(CHECK_META)) {
      expect(['quick', 'moderate', 'project']).toContain(m.effort);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/findings/CheckMeta.test.ts`
Expected: FAIL — cannot find module `CheckMeta.js`.

- [ ] **Step 3: Write CheckMeta with a real starter set**

```ts
// src/findings/CheckMeta.ts
export interface CheckMeta {
  effort: 'quick' | 'moderate' | 'project';
  impact: string;
}

export const CHECK_META: Record<string, CheckMeta> = {
  'internal-user-mfa': { effort: 'quick',
    impact: 'A stolen or guessed admin password grants full org access with no second factor to stop it.' },
  'guest-executable-apex': { effort: 'project',
    impact: 'Unauthenticated web users can execute Apex that bypasses sharing — bulk record exfiltration without login.' },
  'hardcoded-credentials': { effort: 'moderate',
    impact: 'Secrets embedded in Apex can be read by anyone with code access and reused to reach connected systems.' },
  // … one entry per registered check id (see Task 8 for the completeness list)
};

export function getCheckMeta(id: string): CheckMeta | undefined {
  return CHECK_META[id];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/findings/CheckMeta.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/findings/CheckMeta.ts test/unit/findings/CheckMeta.test.ts
git commit -m "feat(findings): CheckMeta effort + impact metadata (starter set)"
```

---

### Task 8: CheckMeta completeness guard + fill remaining entries

**Files:**
- Modify: `src/findings/CheckMeta.ts` (add remaining entries)
- Test: `test/unit/findings/CheckMeta.test.ts` (extend)

- [ ] **Step 1: Write the failing completeness test**

Add to `test/unit/findings/CheckMeta.test.ts`:

```ts
import { CHECKS } from '../../../src/checks/registry.js';
import { CHECK_META } from '../../../src/findings/CheckMeta.js';

it('every registered check has a CheckMeta entry', () => {
  const missing = CHECKS.map((c) => c.id).filter((id) => !CHECK_META[id]);
  expect(missing).toEqual([]);
});
```

- [ ] **Step 2: Run test to see which checks are missing**

Run: `npm test -- test/unit/findings/CheckMeta.test.ts`
Expected: FAIL — the assertion prints the array of missing check ids.

- [ ] **Step 3: Author a CheckMeta entry for every missing id**

For each id printed, add an entry to `CHECK_META`. Effort heuristic: config toggle/single setting = `quick`; multi-record cleanup or policy rollout = `moderate`; code/architecture change across many components = `project`. Impact = one sentence: *how it's abused → what incident results* (concrete, attacker-eye). Use the check's `name`/`description` (in `src/checks/impl/<Name>Check.ts`) for context.

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/findings/CheckMeta.test.ts`
Expected: PASS — no missing ids.

- [ ] **Step 5: Full build + suite**

Run: `npm run build && npm test`
Expected: build clean; all suites green.

- [ ] **Step 6: Commit**

```bash
git add src/findings/CheckMeta.ts test/unit/findings/CheckMeta.test.ts
git commit -m "feat(findings): complete CheckMeta coverage + completeness guard"
```

---

## Self-Review

**Spec coverage (phases 1–2):**
- Sourced `ControlDef` model (id/version/title/requirement/sourceRef/verified) → Task 1.
- Universal catalogs migrated (OWASP/SOC2/ISO) + SBS → Tasks 1–2.
- Thin `checkId → controlId[]` mapping → Task 3.
- Guard: referential integrity → Task 3; completeness → Task 6; provenance gate (requireVerified excludes `verified:false`) → Task 4.
- Resolve with framework-pack selection → Task 4 (`packFrameworks`, `resolveControls`).
- `CheckEngine` migration; existing renderers keep working via id-string `getComplianceTags` shim → Task 5.
- `CheckMeta` (effort + impact) + completeness guard → Tasks 7–8.
- Version pinning: each `ControlDef.version` set; surfaced later by the renderer plan. ✓ (data present here.)

**Deferred to later plans (correctly out of scope):** the `executive` renderer, the matrix rendering + "pending verification" notice, HIPAA/GDPR/HISO/Privacy-Act/NZISM catalogs, the verification worksheet, the `--frameworks`/`--top`/`--branding` flags. None are required for this plan's software to build and pass.

**Placeholder scan:** Catalog *content* (Task 2 SOC2/ISO/SBS bodies, Task 8 remaining CheckMeta) is specified by exact id inventory + source + worked example + heuristic, not vague instruction — acceptable bulk data-entry, all `verified:false` per the provenance model. No `TODO`/`TBD` left in code steps.

**Type consistency:** `Framework`, `ControlDef`, `FrameworkPack` (Task 1) are used unchanged in Tasks 2–4. `getControl` (Task 1) used in Tasks 3–4. `getComplianceTags` keeps the exact name/signature of the old export (Task 4/5) so CheckEngine's call site is untouched. `CHECK_CONTROL_MAP` name consistent Tasks 3/4/6. `getCheckMeta`/`CHECK_META` consistent Tasks 7/8.
