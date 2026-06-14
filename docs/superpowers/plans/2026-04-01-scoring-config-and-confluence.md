# Scoring Config Flag + Confluence Admin Guide — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--scoring-config` flag to `sf audit security` that accepts a JSON file with custom risk weights, per-check weights, and grade thresholds; then produce a Confluence admin guide documenting the full plugin.

**Architecture:** A new `ScoringConfig` type + zod schema is defined in `src/findings/ScoringConfig.ts`. A loader (`loadScoringConfig.ts`) reads, validates, and deep-merges the user file onto built-in defaults. `CheckEngine` tags every finding with `checkId` so scoring can apply per-check weights. `buildAuditResult` accepts an optional `ScoringConfig`. The command reads `--scoring-config`, loads the config, and passes it into the engine.

**Tech Stack:** TypeScript, zod (already a dependency), Jest, `@salesforce/sf-plugins-core` (SfCommand + Flags)

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `src/findings/ScoringConfig.ts` | **Create** | TypeScript types + zod schema for the config |
| `src/findings/loadScoringConfig.ts` | **Create** | File loading, JSON parse, zod validation, merge, unknown-key warnings |
| `src/findings/Finding.ts` | **Modify** | Add `checkId: string` field |
| `src/findings/scoring.ts` | **Modify** | Accept `ScoringConfig`, use `checkId` for weight lookup, config-driven grade logic |
| `src/checks/CheckEngine.ts` | **Modify** | Tag findings with `checkId: check.id` after each check runs; accept + pass `ScoringConfig` |
| `src/commands/audit/security.ts` | **Modify** | Add `--scoring-config` flag, load config, pass to engine |
| `config/scoring.json` | **Modify** | Extend with `gradeThresholds` and `checkWeights` (becomes the shipped default) |
| `config/scoring.sample.json` | **Create** | All 22 check IDs with default weights — copy-paste starter for admins |
| `test/unit/findings/scoring.test.ts` | **Modify** | Add tests for config-driven weight + grade logic |
| `test/unit/findings/loadScoringConfig.test.ts` | **Create** | Tests for loading, validation, merge, and unknown-key warnings |
| `docs/confluence/sf-audit-admin-guide.md` | **Create** | Confluence page content (plain Markdown, paste into Confluence) |

---

## Task 1: Add `checkId` to `Finding` and tag findings in `CheckEngine`

**Files:**
- Modify: `src/findings/Finding.ts`
- Modify: `src/checks/CheckEngine.ts`

- [ ] **Step 1: Add `checkId` to the Finding interface**

Edit `src/findings/Finding.ts`:

```typescript
import type { RiskLevel } from './RiskLevel.js';

export interface AffectedItem {
  label: string;
  url?: string;
  note?: string;
}

export interface Finding {
  id: string;
  checkId: string;        // ← new: the ID of the check that produced this finding
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: AffectedItem[];
}
```

- [ ] **Step 2: Tag findings with `checkId` in `CheckEngine.run()`**

Edit `src/checks/CheckEngine.ts`. In the `run()` method, replace:

```typescript
      try {
        const result = await check.run(this.ctx);
        findings.push(...result.findings);
```

with:

```typescript
      try {
        const result = await check.run(this.ctx);
        findings.push(...result.findings.map((f) => ({ ...f, checkId: check.id })));
```

Also update `buildErrorFinding` to include `checkId`:

```typescript
function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    id: `${check.id}-error`,
    checkId: check.id,           // ← new
    category: check.category,
    riskLevel: 'INFO',
    title: `${check.name}: check failed`,
    detail: `This check encountered an error and could not complete: ${msg}`,
    remediation:
      'Review the error message and verify the running user has the required permissions.',
  };
}
```

- [ ] **Step 3: Build to verify no type errors**

```bash
cd cloudcounsel-sf-plugin-audit
npm run build
```

Expected: clean compile, no errors.

- [ ] **Step 4: Run existing tests to verify nothing broke**

```bash
npm test
```

Expected: all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/findings/Finding.ts src/checks/CheckEngine.ts
git commit -m "feat: add checkId to Finding, tag findings in CheckEngine"
```

---

## Task 2: Define `ScoringConfig` type and zod schema

**Files:**
- Create: `src/findings/ScoringConfig.ts`
- Create: `test/unit/findings/ScoringConfig.test.ts`

- [ ] **Step 1: Write the failing test**

Create `test/unit/findings/ScoringConfig.test.ts`:

```typescript
import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';

describe('scoringConfigSchema', () => {
  it('accepts a full valid config', () => {
    const input = {
      riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
      checkWeights: { 'apex-sharing': 5 },
      gradeThresholds: {
        A: { minScore: 85, maxHigh: 0 },
        B: { minScore: 70, maxHigh: 1 },
        C: { minScore: 55, maxHigh: 3 },
        D: { minScore: 40, maxCritical: 0 },
        F: {},
      },
    };
    expect(() => scoringConfigSchema.parse(input)).not.toThrow();
  });

  it('accepts an empty object (all defaults)', () => {
    expect(() => scoringConfigSchema.parse({})).not.toThrow();
  });

  it('rejects negative risk scores', () => {
    expect(() =>
      scoringConfigSchema.parse({ riskScores: { CRITICAL: -1, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }),
    ).toThrow();
  });

  it('rejects non-integer risk scores', () => {
    expect(() =>
      scoringConfigSchema.parse({ riskScores: { CRITICAL: 1.5, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }),
    ).toThrow();
  });

  it('rejects negative check weights', () => {
    expect(() =>
      scoringConfigSchema.parse({ checkWeights: { 'apex-sharing': -1 } }),
    ).toThrow();
  });

  it('DEFAULT_SCORING_CONFIG has all five risk levels', () => {
    expect(DEFAULT_SCORING_CONFIG.riskScores.CRITICAL).toBe(10);
    expect(DEFAULT_SCORING_CONFIG.riskScores.HIGH).toBe(7);
    expect(DEFAULT_SCORING_CONFIG.riskScores.MEDIUM).toBe(4);
    expect(DEFAULT_SCORING_CONFIG.riskScores.LOW).toBe(1);
    expect(DEFAULT_SCORING_CONFIG.riskScores.INFO).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
npm test -- --testPathPattern="ScoringConfig"
```

Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/findings/ScoringConfig.ts`**

```typescript
import { z } from 'zod';
import type { RiskLevel } from './RiskLevel.js';

const nonNegativeInt = z.number().int().nonnegative();

export const scoringConfigSchema = z.object({
  riskScores: z
    .object({
      CRITICAL: nonNegativeInt,
      HIGH: nonNegativeInt,
      MEDIUM: nonNegativeInt,
      LOW: nonNegativeInt,
      INFO: nonNegativeInt,
    })
    .optional(),
  checkWeights: z.record(z.string(), nonNegativeInt).optional(),
  gradeThresholds: z
    .object({
      A: z.object({ minScore: nonNegativeInt.optional(), maxCritical: nonNegativeInt.optional(), maxHigh: nonNegativeInt.optional(), maxMedium: nonNegativeInt.optional() }).optional(),
      B: z.object({ minScore: nonNegativeInt.optional(), maxCritical: nonNegativeInt.optional(), maxHigh: nonNegativeInt.optional(), maxMedium: nonNegativeInt.optional() }).optional(),
      C: z.object({ minScore: nonNegativeInt.optional(), maxCritical: nonNegativeInt.optional(), maxHigh: nonNegativeInt.optional(), maxMedium: nonNegativeInt.optional() }).optional(),
      D: z.object({ minScore: nonNegativeInt.optional(), maxCritical: nonNegativeInt.optional(), maxHigh: nonNegativeInt.optional(), maxMedium: nonNegativeInt.optional() }).optional(),
      F: z.object({ minScore: nonNegativeInt.optional(), maxCritical: nonNegativeInt.optional(), maxHigh: nonNegativeInt.optional(), maxMedium: nonNegativeInt.optional() }).optional(),
    })
    .optional(),
});

export type ScoringConfigInput = z.infer<typeof scoringConfigSchema>;

export interface GradeConditions {
  minScore?: number;
  maxCritical?: number;
  maxHigh?: number;
  maxMedium?: number;
}

export interface ScoringConfig {
  riskScores: Record<RiskLevel, number>;
  checkWeights: Record<string, number>;
  gradeThresholds: Record<'A' | 'B' | 'C' | 'D' | 'F', GradeConditions>;
}

export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
  checkWeights: {},
  gradeThresholds: {
    A: { minScore: 85, maxHigh: 0 },
    B: { minScore: 70, maxHigh: 1 },
    C: { minScore: 55, maxHigh: 3 },
    D: { minScore: 40, maxCritical: 0 },
    F: {},
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

```bash
npm test -- --testPathPattern="ScoringConfig"
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/findings/ScoringConfig.ts test/unit/findings/ScoringConfig.test.ts
git commit -m "feat: add ScoringConfig type, zod schema, and defaults"
```

---

## Task 3: Config loader — read, validate, merge, warn

**Files:**
- Create: `src/findings/loadScoringConfig.ts`
- Create: `test/unit/findings/loadScoringConfig.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `test/unit/findings/loadScoringConfig.test.ts`:

```typescript
import * as fs from 'node:fs';
import { loadScoringConfig } from '../../../src/findings/loadScoringConfig.js';
import { DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';

jest.mock('node:fs');
const mockReadFileSync = fs.readFileSync as jest.MockedFunction<typeof fs.readFileSync>;

const KNOWN_CHECK_IDS = new Set([
  'apex-sharing', 'api-limits', 'audit-trail', 'code-security', 'connected-apps',
  'custom-settings', 'field-level-security', 'flows-without-sharing', 'guest-user-access',
  'hardcoded-credentials', 'health-check', 'inactive-users', 'ip-restrictions',
  'login-session', 'named-credentials', 'password-session-policy', 'permissions',
  'public-group-sharing', 'remote-sites', 'scheduled-apex', 'sharing-model', 'users-and-admins',
]);

describe('loadScoringConfig', () => {
  const warn = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns defaults when no path is provided', () => {
    const result = loadScoringConfig(undefined, KNOWN_CHECK_IDS, warn);
    expect(result).toEqual(DEFAULT_SCORING_CONFIG);
    expect(warn).not.toHaveBeenCalled();
  });

  it('deep-merges overrides onto defaults', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ riskScores: { CRITICAL: 15, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(result.riskScores.CRITICAL).toBe(15);
    expect(result.riskScores.HIGH).toBe(7); // unchanged default
    expect(result.checkWeights).toEqual({}); // default preserved
  });

  it('merges checkWeights onto empty default', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ checkWeights: { 'apex-sharing': 12 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(result.checkWeights['apex-sharing']).toBe(12);
  });

  it('warns on unknown check IDs but continues', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ checkWeights: { 'not-a-check': 5 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('not-a-check'));
    expect(result.checkWeights['not-a-check']).toBeUndefined(); // unknown keys are dropped
  });

  it('throws on invalid JSON', () => {
    mockReadFileSync.mockReturnValue('not valid json');
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn)).toThrow();
  });

  it('throws on schema validation failure', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ riskScores: { CRITICAL: -1, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn)).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
npm test -- --testPathPattern="loadScoringConfig"
```

Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/findings/loadScoringConfig.ts`**

```typescript
import * as fs from 'node:fs';
import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig } from './ScoringConfig.js';

export function loadScoringConfig(
  filePath: string | undefined,
  knownCheckIds: Set<string>,
  warn: (msg: string) => void,
): ScoringConfig {
  if (!filePath) return DEFAULT_SCORING_CONFIG;

  const raw = fs.readFileSync(filePath, 'utf-8');
  const parsed: unknown = JSON.parse(raw);
  const validated = scoringConfigSchema.parse(parsed); // throws ZodError on failure

  // Warn on unknown check IDs and drop them
  const safeCheckWeights: Record<string, number> = {};
  for (const [id, weight] of Object.entries(validated.checkWeights ?? {})) {
    if (!knownCheckIds.has(id)) {
      warn(`Unknown check ID in --scoring-config checkWeights: '${id}'. Run 'sf audit list' to see valid IDs. Skipping.`);
    } else {
      safeCheckWeights[id] = weight;
    }
  }

  return {
    riskScores: { ...DEFAULT_SCORING_CONFIG.riskScores, ...(validated.riskScores ?? {}) },
    checkWeights: safeCheckWeights,
    gradeThresholds: {
      A: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.A, ...(validated.gradeThresholds?.A ?? {}) },
      B: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.B, ...(validated.gradeThresholds?.B ?? {}) },
      C: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.C, ...(validated.gradeThresholds?.C ?? {}) },
      D: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.D, ...(validated.gradeThresholds?.D ?? {}) },
      F: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.F, ...(validated.gradeThresholds?.F ?? {}) },
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
npm test -- --testPathPattern="loadScoringConfig"
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/findings/loadScoringConfig.ts test/unit/findings/loadScoringConfig.test.ts
git commit -m "feat: add loadScoringConfig with zod validation and merge logic"
```

---

## Task 4: Update `scoring.ts` to use `ScoringConfig`

**Files:**
- Modify: `src/findings/scoring.ts`
- Modify: `test/unit/findings/scoring.test.ts`

- [ ] **Step 1: Add new test cases to `scoring.test.ts`**

Add to the end of the `describe('buildAuditResult')` block in `test/unit/findings/scoring.test.ts`:

```typescript
  describe('with custom ScoringConfig', () => {
    it('uses checkWeights override for matching checkId', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: { 'my-check': 10 },
        gradeThresholds: {
          A: { minScore: 85, maxHigh: 0 },
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      // A LOW finding from 'my-check' should score 10, not 1
      const f: Finding = { id: 'f1', checkId: 'my-check', category: 'Test', riskLevel: 'LOW', title: 'T', detail: 'd', remediation: 'r' };
      const result = buildAuditResult(makeCtx(), [f], {}, config);
      // totalScore=10, maxPossible=10 → healthScore=0
      expect(result.healthScore).toBe(0);
    });

    it('falls back to riskScores for checkIds not in checkWeights', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: {},
        gradeThresholds: {
          A: { minScore: 85, maxHigh: 0 },
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      const f: Finding = { id: 'f1', checkId: 'other-check', category: 'Test', riskLevel: 'INFO', title: 'T', detail: 'd', remediation: 'r' };
      const result = buildAuditResult(makeCtx(), [f], {}, config);
      expect(result.healthScore).toBe(100); // INFO=0, no penalty
    });

    it('applies config-driven grade thresholds', () => {
      const config = {
        riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
        checkWeights: {},
        gradeThresholds: {
          A: { minScore: 95 }, // raised threshold
          B: { minScore: 70, maxHigh: 1 },
          C: { minScore: 55, maxHigh: 3 },
          D: { minScore: 40, maxCritical: 0 },
          F: {},
        },
      };
      // Zero findings → healthScore=100, but A requires minScore=95 → should still be A
      const result = buildAuditResult(makeCtx(), [], {}, config);
      expect(result.grade).toBe('A');
    });
  });
```

Also update the `finding()` helper to include `checkId`:

```typescript
function finding(riskLevel: Finding['riskLevel'], id = 'f1'): Finding {
  return { id, checkId: 'test-check', category: 'Test', riskLevel, title: 'T', detail: 'd', remediation: 'r' };
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- --testPathPattern="scoring.test"
```

Expected: FAIL — `buildAuditResult` doesn't accept a fourth argument yet, and `finding()` type error on `checkId`.

- [ ] **Step 3: Rewrite `src/findings/scoring.ts`**

```typescript
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import type { AuditContext } from '../context/AuditContext.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';
import { DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig } from './ScoringConfig.js';

type Grade = AuditResult['grade'];

function meetsConditions(
  conditions: ScoringConfig['gradeThresholds'][Grade],
  healthScore: number,
  criticalCount: number,
  highCount: number,
  mediumCount: number,
): boolean {
  if (conditions.minScore !== undefined && healthScore < conditions.minScore) return false;
  if (conditions.maxCritical !== undefined && criticalCount > conditions.maxCritical) return false;
  if (conditions.maxHigh !== undefined && highCount > conditions.maxHigh) return false;
  if (conditions.maxMedium !== undefined && mediumCount > conditions.maxMedium) return false;
  return true;
}

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
): AuditResult {
  const totalScore = findings.reduce(
    (sum, f) => sum + (config.checkWeights[f.checkId] ?? config.riskScores[f.riskLevel]),
    0,
  );
  const maxPossible = findings.length * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalScore / Math.max(maxPossible, 1)) * 100),
  );

  const criticalCount = findings.filter((f) => f.riskLevel === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.riskLevel === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.riskLevel === 'MEDIUM').length;

  const grades: Grade[] = ['A', 'B', 'C', 'D'];
  let grade: Grade = 'F';
  for (const g of grades) {
    if (meetsConditions(config.gradeThresholds[g], healthScore, criticalCount, highCount, mediumCount)) {
      grade = g;
      break;
    }
  }

  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore,
    grade,
  };
}
```

- [ ] **Step 4: Run all tests to verify they pass**

```bash
npm test
```

Expected: all tests pass including new ones.

- [ ] **Step 5: Commit**

```bash
git add src/findings/scoring.ts src/findings/ScoringConfig.ts test/unit/findings/scoring.test.ts
git commit -m "feat: config-driven scoring — per-check weights and grade thresholds"
```

---

## Task 5: Thread `ScoringConfig` through `CheckEngine`

**Files:**
- Modify: `src/checks/CheckEngine.ts`

- [ ] **Step 1: Update `CheckEngine` to accept and pass `ScoringConfig`**

Edit `src/checks/CheckEngine.ts`:

```typescript
import type { SecurityCheck } from './SecurityCheck.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditResult } from '../findings/AuditResult.js';
import type { ScoringConfig } from '../findings/ScoringConfig.js';
import { buildAuditResult } from '../findings/scoring.js';

function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    id: `${check.id}-error`,
    checkId: check.id,
    category: check.category,
    riskLevel: 'INFO',
    title: `${check.name}: check failed`,
    detail: `This check encountered an error and could not complete: ${msg}`,
    remediation:
      'Review the error message and verify the running user has the required permissions.',
  };
}

export class CheckEngine {
  constructor(
    private readonly checks: SecurityCheck[],
    private readonly ctx: AuditContext,
    private readonly scoringConfig?: ScoringConfig,
  ) {
    this.validateCacheOrdering();
  }

  async run(
    onProgress?: (current: number, total: number, checkName: string) => void,
  ): Promise<AuditResult> {
    const findings: Finding[] = [];
    let metrics: Partial<OrgMetrics> = {};
    const total = this.checks.length;

    for (let i = 0; i < total; i++) {
      const check = this.checks[i];
      onProgress?.(i + 1, total, check.name);
      try {
        const result = await check.run(this.ctx);
        findings.push(...result.findings.map((f) => ({ ...f, checkId: check.id })));
        if (result.metrics) {
          metrics = { ...metrics, ...result.metrics };
        }
      } catch (err) {
        findings.push(buildErrorFinding(check, err));
      }
    }

    return buildAuditResult(this.ctx, findings, metrics, this.scoringConfig);
  }

  private validateCacheOrdering(): void {
    const populated = new Set<keyof AuditCache>();
    for (const check of this.checks) {
      for (const key of check.dependsOnCache ?? []) {
        if (!populated.has(key)) {
          throw new Error(
            `Check '${check.name}' depends on cache key '${key}' ` +
              `but no preceding check declares it in populatesCache.`,
          );
        }
      }
      for (const key of check.populatesCache ?? []) {
        populated.add(key);
      }
    }
  }
}
```

- [ ] **Step 2: Build and run all tests**

```bash
npm run build && npm test
```

Expected: clean compile, all tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/checks/CheckEngine.ts
git commit -m "feat: thread ScoringConfig through CheckEngine"
```

---

## Task 6: Add `--scoring-config` flag to the `security` command

**Files:**
- Modify: `src/commands/audit/security.ts`

- [ ] **Step 1: Add the flag and wire up config loading**

Edit `src/commands/audit/security.ts`. Add the import at the top:

```typescript
import { loadScoringConfig } from '../../findings/loadScoringConfig.js';
import { CHECKS } from '../../checks/registry.js';
```

Add the flag inside `public static flags`:

```typescript
    'scoring-config': Flags.string({
      summary: 'Path to a custom scoring config JSON file. Merges with defaults.',
      helpValue: './hnz-scoring.json',
    }),
```

In the `run()` method, after resolving `orgInfo` and before creating the engine, add:

```typescript
    const knownCheckIds = new Set(CHECKS.map((c) => c.id));
    const scoringConfig = loadScoringConfig(
      flags['scoring-config'],
      knownCheckIds,
      (msg) => this.warn(msg),
    );
```

Pass `scoringConfig` to `CheckEngine`:

```typescript
    const engine = new CheckEngine(checksToRun, ctx, scoringConfig);
```

- [ ] **Step 2: Build and verify**

```bash
npm run build
```

Expected: clean compile.

- [ ] **Step 3: Smoke-test the flag help output**

```bash
sf audit security --help
```

Expected: `--scoring-config` appears in the flags list.

- [ ] **Step 4: Run all tests**

```bash
npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/commands/audit/security.ts
git commit -m "feat: add --scoring-config flag to sf audit security"
```

---

## Task 7: Ship sample config and update default `scoring.json`

**Files:**
- Modify: `config/scoring.json`
- Create: `config/scoring.sample.json`

- [ ] **Step 1: Extend `config/scoring.json` with full defaults**

Replace the content of `config/scoring.json` with:

```json
{
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {},
  "gradeThresholds": {
    "A": { "minScore": 85, "maxHigh": 0 },
    "B": { "minScore": 70, "maxHigh": 1 },
    "C": { "minScore": 55, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

- [ ] **Step 2: Create `config/scoring.sample.json`**

```json
{
  "_comment": "Copy this file, adjust values to fit your org's risk appetite, and pass it with --scoring-config <path>. All sections are optional — omit any section to keep the default.",
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {
    "_comment": "Override the weight for a specific check regardless of its riskLevel. Remove this _comment key before using.",
    "apex-sharing": 7,
    "api-limits": 4,
    "audit-trail": 4,
    "code-security": 4,
    "connected-apps": 7,
    "custom-settings": 4,
    "field-level-security": 7,
    "flows-without-sharing": 7,
    "guest-user-access": 10,
    "hardcoded-credentials": 10,
    "health-check": 7,
    "inactive-users": 4,
    "ip-restrictions": 7,
    "login-session": 4,
    "named-credentials": 1,
    "password-session-policy": 7,
    "permissions": 4,
    "public-group-sharing": 4,
    "remote-sites": 4,
    "scheduled-apex": 1,
    "sharing-model": 7,
    "users-and-admins": 10
  },
  "gradeThresholds": {
    "A": { "minScore": 85, "maxHigh": 0 },
    "B": { "minScore": 70, "maxHigh": 1 },
    "C": { "minScore": 55, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

- [ ] **Step 3: Run all tests**

```bash
npm test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add config/scoring.json config/scoring.sample.json
git commit -m "feat: extend scoring.json with grade thresholds; add scoring.sample.json for admins"
```

---

## Task 8: Write the Confluence admin guide

**Files:**
- Create: `docs/confluence/sf-audit-admin-guide.md`

- [ ] **Step 1: Create the docs directory and write the guide**

```bash
mkdir -p docs/confluence
```

Create `docs/confluence/sf-audit-admin-guide.md` with the following content:

```markdown
# sf-audit Plugin — Admin & Ops Guide

---

## Overview

`sf-audit` is a Salesforce CLI plugin that runs a security audit against any connected org and produces a report. It checks 22 areas across identity, data security, integrations, code, and platform health — then gives the org a score out of 100 and a grade from A to F.

It's designed to be run by admins on demand, or wired into a CI/CD pipeline to flag regressions before deployment.

---

## Requirements

Before running an audit, make sure you have:

- **Node.js 18+**
- **Salesforce CLI v2+** (`sf --version` to check)
- **An authenticated org** — the running user needs Read access to setup objects (User, PermissionSet, ApexClass, Flow, etc.) and access to the Tooling API. A System Administrator profile covers this.

---

## Installation

Install the plugin once per machine:

```bash
sf plugins install @cclabsnz/sf-audit
```

Verify it installed:

```bash
sf plugins list
sf audit --help
```

---

## Running an Audit

### Basic usage

```bash
sf audit security --target-org <orgAlias>
```

This runs all 22 checks and writes an HTML report to your current directory.

### Sandbox vs production

There's no difference in the command — the org type is detected automatically and shown in the report header. The recommended workflow for HNZ is:

1. Audit the sandbox first: `sf audit security --target-org HNZ_UAT`
2. Review the report and remediate findings
3. Audit production before each release: `sf audit security --target-org HNZ_PROD --fail-on HIGH`

### All flags

| Flag | Default | What it does |
|------|---------|--------------|
| `--target-org` | *(required)* | Org alias or username to audit |
| `--format` / `-f` | `html` | Output format(s). Comma-separated: `html`, `md`, `json` |
| `--output` / `-o` | `.` | Directory to write the report |
| `--fail-on` | — | Exit with code 1 if any finding is at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--checks` | *(all)* | Comma-separated check IDs to run. Omit to run all. See `sf audit list` for IDs. |
| `--scoring-config` | *(defaults)* | Path to a custom scoring JSON file. See [Customising the Scoring](#customising-the-scoring). |

### Examples

```bash
# HTML report, written to current directory
sf audit security --target-org HNZ_PROD

# JSON + Markdown reports, written to ./reports
sf audit security --target-org HNZ_PROD --format json,md --output ./reports

# Fail the pipeline if any HIGH or CRITICAL findings exist
sf audit security --target-org HNZ_PROD --fail-on HIGH

# Run only two specific checks
sf audit security --target-org HNZ_UAT --checks hardcoded-credentials,guest-user-access

# Use a custom scoring config
sf audit security --target-org HNZ_PROD --scoring-config ./hnz-scoring.json
```

Report files are named `sf-audit-<orgId>-<timestamp>.<ext>` so multiple runs never overwrite each other.

---

## Understanding Results

### Health score

The health score is a number from 0 to 100. Higher is better. It represents how far the org's findings are from the worst-case scenario given the checks that produced findings.

### Grade

| Grade | What it means |
|-------|--------------|
| **A** | Score ≥ 85, no HIGH findings |
| **B** | Score ≥ 70, ≤ 1 HIGH finding |
| **C** | Score ≥ 55, ≤ 3 HIGH findings |
| **D** | Score ≥ 40, no CRITICAL findings |
| **F** | Score < 40 or any CRITICAL finding |

Grades are evaluated from A down. The org gets the highest grade whose conditions are all met.

### Finding severity levels

| Level | What it means |
|-------|--------------|
| **CRITICAL** | Immediate risk. Hardcoded credentials, guest user object access, etc. |
| **HIGH** | Significant exposure that should be addressed soon. |
| **MEDIUM** | Worth reviewing. Low immediate risk but can compound. |
| **LOW** | Informational or minor. Good hygiene to address. |
| **INFO** | No risk. Context only. |

---

## How the Score is Calculated

Each finding is assigned a weight based on its severity:

| Severity | Default weight |
|----------|---------------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The health score formula is:

```
health score = 100 − round((sum of finding weights / max possible weight) × 100)
```

`max possible weight` = number of findings × 10 (i.e. if every finding were CRITICAL).

You can also assign a weight directly to a specific check, which overrides the severity-based weight for that check's findings. See [Customising the Scoring](#customising-the-scoring).

---

## Customising the Scoring

HNZ orgs may want to weight some checks more heavily than others — for example, treating hardcoded credentials as more critical than inactive users.

### The `--scoring-config` flag

Pass a JSON file at runtime:

```bash
sf audit security --target-org HNZ_PROD --scoring-config ./hnz-scoring.json
```

The file merges with the built-in defaults. You only need to include the keys you want to change.

### Sample config

A starter file with all 22 check IDs and default weights is included with the plugin at `config/scoring.sample.json`. Copy it and adjust:

```json
{
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {
    "apex-sharing": 7,
    "api-limits": 4,
    "audit-trail": 4,
    "code-security": 4,
    "connected-apps": 7,
    "custom-settings": 4,
    "field-level-security": 7,
    "flows-without-sharing": 7,
    "guest-user-access": 10,
    "hardcoded-credentials": 10,
    "health-check": 7,
    "inactive-users": 4,
    "ip-restrictions": 7,
    "login-session": 4,
    "named-credentials": 1,
    "password-session-policy": 7,
    "permissions": 4,
    "public-group-sharing": 4,
    "remote-sites": 4,
    "scheduled-apex": 1,
    "sharing-model": 7,
    "users-and-admins": 10
  },
  "gradeThresholds": {
    "A": { "minScore": 85, "maxHigh": 0 },
    "B": { "minScore": 70, "maxHigh": 1 },
    "C": { "minScore": 55, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

### What each section does

**`riskScores`** — base weight per severity level. All checks not listed in `checkWeights` use these.

**`checkWeights`** — per-check weight override. When a check ID is listed here, its findings always use this weight regardless of their severity. Unknown check IDs produce a warning and are ignored — the run continues.

**`gradeThresholds`** — conditions for each grade. Grades are evaluated A → B → C → D → F. The first grade whose conditions are all satisfied wins. `F` is the automatic fallback. Each grade supports:

| Key | Meaning |
|-----|---------|
| `minScore` | Health score must be ≥ this value |
| `maxCritical` | CRITICAL findings must be ≤ this count |
| `maxHigh` | HIGH findings must be ≤ this count |
| `maxMedium` | MEDIUM findings must be ≤ this count |

---

## CI/CD Integration

Use `--fail-on` to fail a pipeline when findings breach a threshold:

```bash
sf audit security --target-org HNZ_PROD --fail-on HIGH
```

Exit codes:
- `0` — audit completed, no findings at or above the threshold
- `1` — one or more findings at or above `--fail-on` level

The plugin prints a summary of threshold-breaching findings before exiting.

---

## Troubleshooting

### "INSUFFICIENT_ACCESS" or missing data in the report

The running user doesn't have access to one or more setup objects. Required permissions:

- Read on: User, PermissionSet, PermissionSetAssignment, Profile, ApexClass, Flow, ConnectedApplication, RemoteSiteSetting, NamedCredential, CustomPermission, Group, GroupMember, SetupAuditTrail
- Tooling API access
- View Setup and Configuration permission

A System Administrator profile covers all of these.

### "Unknown check ID(s)" warning

You passed a `--checks` flag with an ID that doesn't exist. Run `sf audit list` to see all valid check IDs.

### "Unknown check ID in --scoring-config checkWeights" warning

A check ID in your `--scoring-config` file doesn't match any known check. The ID is skipped and the run continues. Run `sf audit list` to verify check IDs.

### Report not written / permission error

Check that the `--output` directory exists and the current user has write access to it.

### Plugin not found after install

Restart your terminal or run `sf plugins list` to confirm the install completed. If the plugin is missing, try `sf plugins install @cclabsnz/sf-audit` again.
```

- [ ] **Step 2: Commit**

```bash
git add docs/confluence/sf-audit-admin-guide.md
git commit -m "docs: add HNZ Confluence admin guide for sf-audit plugin"
```

---

## Final verification

- [ ] **Run the full test suite one last time**

```bash
npm run build && npm test
```

Expected: clean compile, all tests pass.

- [ ] **Verify the sample config is accessible**

```bash
cat config/scoring.sample.json | node -e "require('fs');const d=require('fs').readFileSync('/dev/stdin','utf8');JSON.parse(d.replace(/\"_comment\":[^,\n}]+,?/g,'').replace(/,\s*}/g,'}')); console.log('valid JSON');"
```

Expected: `valid JSON`
