# Audit History & Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add time-series audit history and diff capabilities to `@cclabsnz/sf-audit` — auto-archive every run, `sf audit diff` to compare two reports, `sf audit history` to see trends.

**Architecture:** New code lives in `src/history/` (domain types + pure engine + store) and two new commands; existing 23 checks, CheckEngine, QueryRegistry, and all renderers are untouched. The only changes to existing files are +3 lines in `security.ts` (auto-archive) and exports in `index.ts`.

**Tech Stack:** TypeScript ESM, Node `fs`/`os`/`path`, Jest + ts-jest, `@salesforce/sf-plugins-core` (SfCommand/Flags), Chart.js via CDN (history HTML report).

---

## File Map

| File | Status | Responsibility |
|------|--------|---------------|
| `src/history/AuditDiff.ts` | Create | `FindingChange`, `MetricDelta`, `AuditDiff` types |
| `src/history/metricMeta.ts` | Create | Per-metric label + direction lookup |
| `src/history/DiffEngine.ts` | Create | `computeDiff()` pure function |
| `src/history/HistoryStore.ts` | Create | Archive/list/load file I/O |
| `src/renderers/DiffRenderer.ts` | Create | `DiffRenderer` interface |
| `src/renderers/DiffJsonRenderer.ts` | Create | JSON serialisation of `AuditDiff` |
| `src/renderers/DiffHtmlRenderer.ts` | Create | Self-contained HTML diff report |
| `src/renderers/HistoryRenderer.ts` | Create | Terminal table + HTML timeline (Chart.js) |
| `src/commands/audit/diff.ts` | Create | `sf audit diff <baseline> <current>` |
| `src/commands/audit/history.ts` | Create | `sf audit history --target-org` |
| `src/commands/audit/security.ts` | Modify | +3 lines: auto-archive after renderers loop |
| `src/index.ts` | Modify | Export new public types |
| `test/unit/history/DiffEngine.test.ts` | Create | Unit tests — all change type classifications |
| `test/unit/history/HistoryStore.test.ts` | Create | Unit tests using tmp dir |
| `test/unit/renderers/DiffJsonRenderer.test.ts` | Create | Snapshot test |
| `test/unit/renderers/DiffHtmlRenderer.test.ts` | Create | Snapshot test |
| `test/unit/renderers/HistoryRenderer.test.ts` | Create | Terminal table snapshot |
| `README.md` | Modify | Add History & Diff section |

---

## Shared Test Fixtures

These fixtures are referenced in multiple tasks. Define them once — copy them into each test file that needs them.

```typescript
// Shared fixture factory — copy into test files that need it
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

export function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

export const BASELINE = makeResult({
  generatedAt: new Date('2026-03-23T15:10:00Z'),
  healthScore: 64,
  grade: 'D',
  findings: [
    { id: 'f-resolved', checkId: 'c1', category: 'Auth', riskLevel: 'HIGH',    title: 'Old finding',         detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'CRITICAL', title: 'Severity changes',    detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',  title: 'Detail changes',      detail: 'old detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',     title: 'Unchanged finding',   detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 5, codeCoveragePercent: 60, totalActiveUsers: 100 },
});

export const CURRENT = makeResult({
  generatedAt: new Date('2026-04-09T11:22:00Z'),
  healthScore: 81,
  grade: 'B',
  findings: [
    { id: 'f-new',      checkId: 'c5', category: 'Auth', riskLevel: 'CRITICAL', title: 'New finding',        detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'HIGH',     title: 'Severity changes',   detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',  title: 'Detail changes',      detail: 'new detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',     title: 'Unchanged finding',   detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 3, codeCoveragePercent: 75, totalActiveUsers: 100 },
});
```

---

## Task 1: Domain Types — `AuditDiff.ts`

**Files:**
- Create: `src/history/AuditDiff.ts`

No tests needed — this is a pure type file. Types are verified by TypeScript compilation.

- [ ] **Step 1: Create the type file**

```typescript
// src/history/AuditDiff.ts
import type { Finding } from '../findings/Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from '../findings/AuditResult.js';

export type FindingChangeType =
  | 'new'
  | 'resolved'
  | 'severity-changed'
  | 'detail-changed'
  | 'unchanged';

export interface FindingChange {
  type: FindingChangeType;
  finding: Finding;    // current finding (or the resolved finding if type === 'resolved')
  previous?: Finding;  // populated for 'severity-changed' and 'detail-changed'
}

export interface MetricDelta {
  key: keyof OrgMetrics;
  label: string;
  before: number;
  after: number;
  delta: number;       // after - before
  direction: 'improved' | 'degraded' | 'neutral';
}

export interface AuditDiff {
  baseline: AuditResult;
  current: AuditResult;
  findingChanges: FindingChange[];
  metricDeltas: MetricDelta[];  // only entries where before !== after
  scoreDelta: number;           // current.healthScore - baseline.healthScore
  gradeDelta: string;           // e.g. "D → B" or "unchanged"
}
```

- [ ] **Step 2: Verify it compiles**

Run: `npm run build`
Expected: exit 0, no TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add src/history/AuditDiff.ts
git commit -m "feat(history): add AuditDiff domain types"
```

---

## Task 2: Metric Metadata — `metricMeta.ts`

**Files:**
- Create: `src/history/metricMeta.ts`

- [ ] **Step 1: Create the file**

```typescript
// src/history/metricMeta.ts
import type { OrgMetrics } from '../context/OrgMetrics.js';

export interface MetricMeta {
  label: string;
  /** Which direction means "getting better"? */
  improvedWhen: 'higher' | 'lower' | 'neutral';
}

// Every key of OrgMetrics must have an entry here.
export const METRIC_META: Record<keyof OrgMetrics, MetricMeta> = {
  totalActiveUsers:           { label: 'Total Active Users',             improvedWhen: 'neutral' },
  modifyAllDataUsersCount:    { label: 'Modify All Data Users',          improvedWhen: 'lower'   },
  viewAllDataUsersCount:      { label: 'View All Data Users',            improvedWhen: 'lower'   },
  permissionSetCount:         { label: 'Permission Sets',                improvedWhen: 'neutral' },
  profileCount:               { label: 'Profiles',                       improvedWhen: 'neutral' },
  apexClassCount:             { label: 'Apex Classes',                   improvedWhen: 'neutral' },
  apexTriggerCount:           { label: 'Apex Triggers',                  improvedWhen: 'neutral' },
  codeCoveragePercent:        { label: 'Code Coverage %',                improvedWhen: 'higher'  },
  failedLogins30d:            { label: 'Failed Logins (30d)',            improvedWhen: 'lower'   },
  inactiveUsers90d:           { label: 'Inactive Users (90d)',           improvedWhen: 'lower'   },
  connectedAppsCount:         { label: 'Connected Apps',                 improvedWhen: 'neutral' },
  remoteSitesCount:           { label: 'Remote Site Settings',           improvedWhen: 'neutral' },
  insecureRemoteSitesCount:   { label: 'Insecure Remote Sites',          improvedWhen: 'lower'   },
  namedCredentialsCount:      { label: 'Named Credentials',              improvedWhen: 'neutral' },
  unusedNamedCredentialsCount:{ label: 'Unused Named Credentials',       improvedWhen: 'lower'   },
  healthCheckScore:           { label: 'Health Check Score',             improvedWhen: 'higher'  },
};

export function metricDirection(
  key: keyof OrgMetrics,
  before: number,
  after: number,
): 'improved' | 'degraded' | 'neutral' {
  const meta = METRIC_META[key];
  if (meta.improvedWhen === 'neutral' || before === after) return 'neutral';
  if (meta.improvedWhen === 'higher') return after > before ? 'improved' : 'degraded';
  return after < before ? 'improved' : 'degraded';
}
```

- [ ] **Step 2: Verify it compiles**

Run: `npm run build`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/history/metricMeta.ts
git commit -m "feat(history): add metric metadata direction lookup"
```

---

## Task 3: DiffEngine — Pure Diff Computation

**Files:**
- Create: `src/history/DiffEngine.ts`
- Create: `test/unit/history/DiffEngine.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
// test/unit/history/DiffEngine.test.ts
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const BASELINE = makeResult({
  healthScore: 64,
  grade: 'D',
  findings: [
    { id: 'f-resolved', checkId: 'c1', category: 'Auth', riskLevel: 'HIGH',     title: 'Old finding',       detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'CRITICAL', title: 'Severity changes',  detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',   title: 'Detail changes',    detail: 'old detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',      title: 'Unchanged finding', detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 5, codeCoveragePercent: 60, totalActiveUsers: 100 },
});

const CURRENT = makeResult({
  healthScore: 81,
  grade: 'B',
  findings: [
    { id: 'f-new',      checkId: 'c5', category: 'Auth', riskLevel: 'CRITICAL', title: 'New finding',       detail: 'detail',     remediation: 'fix it' },
    { id: 'f-severity', checkId: 'c2', category: 'Auth', riskLevel: 'HIGH',     title: 'Severity changes',  detail: 'detail',     remediation: 'fix it' },
    { id: 'f-detail',   checkId: 'c3', category: 'Auth', riskLevel: 'MEDIUM',   title: 'Detail changes',    detail: 'new detail', remediation: 'fix it' },
    { id: 'f-unchanged',checkId: 'c4', category: 'Auth', riskLevel: 'LOW',      title: 'Unchanged finding', detail: 'detail',     remediation: 'fix it' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 3, codeCoveragePercent: 75, totalActiveUsers: 100 },
});

describe('computeDiff', () => {
  const diff = computeDiff(BASELINE, CURRENT);

  it('attaches baseline and current', () => {
    expect(diff.baseline).toBe(BASELINE);
    expect(diff.current).toBe(CURRENT);
  });

  it('computes scoreDelta', () => {
    expect(diff.scoreDelta).toBe(17); // 81 - 64
  });

  it('computes gradeDelta', () => {
    expect(diff.gradeDelta).toBe('D → B');
  });

  it('gradeDelta is "unchanged" when grades are equal', () => {
    const sameGrade = computeDiff(BASELINE, makeResult({ grade: 'D', healthScore: 65 }));
    expect(sameGrade.gradeDelta).toBe('unchanged');
  });

  describe('findingChanges', () => {
    it('classifies new finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-new');
      expect(change?.type).toBe('new');
      expect(change?.previous).toBeUndefined();
    });

    it('classifies resolved finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-resolved');
      expect(change?.type).toBe('resolved');
    });

    it('classifies severity-changed finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-severity');
      expect(change?.type).toBe('severity-changed');
      expect(change?.previous?.riskLevel).toBe('CRITICAL');
      expect(change?.finding.riskLevel).toBe('HIGH');
    });

    it('classifies detail-changed finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-detail');
      expect(change?.type).toBe('detail-changed');
      expect(change?.previous?.detail).toBe('old detail');
      expect(change?.finding.detail).toBe('new detail');
    });

    it('classifies unchanged finding', () => {
      const change = diff.findingChanges.find((c) => c.finding.id === 'f-unchanged');
      expect(change?.type).toBe('unchanged');
    });
  });

  describe('metricDeltas', () => {
    it('only includes metrics where before !== after', () => {
      // totalActiveUsers is 100 in both — should be absent
      expect(diff.metricDeltas.find((d) => d.key === 'totalActiveUsers')).toBeUndefined();
    });

    it('marks modifyAllDataUsersCount decrease as improved', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'modifyAllDataUsersCount')!;
      expect(delta.before).toBe(5);
      expect(delta.after).toBe(3);
      expect(delta.delta).toBe(-2);
      expect(delta.direction).toBe('improved');
    });

    it('marks codeCoveragePercent increase as improved', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'codeCoveragePercent')!;
      expect(delta.before).toBe(60);
      expect(delta.after).toBe(75);
      expect(delta.delta).toBe(15);
      expect(delta.direction).toBe('improved');
    });

    it('marks insecureRemoteSitesCount increase as degraded', () => {
      const withInsecure = computeDiff(
        makeResult({ metrics: { ...EMPTY_METRICS, insecureRemoteSitesCount: 0 } }),
        makeResult({ metrics: { ...EMPTY_METRICS, insecureRemoteSitesCount: 2 } }),
      );
      const delta = withInsecure.metricDeltas.find((d) => d.key === 'insecureRemoteSitesCount')!;
      expect(delta.direction).toBe('degraded');
    });

    it('includes human-readable label', () => {
      const delta = diff.metricDeltas.find((d) => d.key === 'modifyAllDataUsersCount')!;
      expect(delta.label).toBe('Modify All Data Users');
    });
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `npm test -- --testPathPattern=DiffEngine`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Implement DiffEngine**

```typescript
// src/history/DiffEngine.ts
import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditDiff, FindingChange, MetricDelta } from './AuditDiff.js';
import { METRIC_META, metricDirection } from './metricMeta.js';

function detailChanged(a: Finding, b: Finding): boolean {
  return (
    a.detail !== b.detail ||
    a.remediation !== b.remediation ||
    JSON.stringify(a.affectedItems) !== JSON.stringify(b.affectedItems)
  );
}

export function computeDiff(baseline: AuditResult, current: AuditResult): AuditDiff {
  const baselineMap = new Map<string, Finding>(baseline.findings.map((f) => [f.id, f]));
  const currentMap  = new Map<string, Finding>(current.findings.map((f) => [f.id, f]));

  const findingChanges: FindingChange[] = [];

  // Walk current findings
  for (const [id, cur] of currentMap) {
    const prev = baselineMap.get(id);
    if (!prev) {
      findingChanges.push({ type: 'new', finding: cur });
    } else if (cur.riskLevel !== prev.riskLevel) {
      findingChanges.push({ type: 'severity-changed', finding: cur, previous: prev });
    } else if (detailChanged(prev, cur)) {
      findingChanges.push({ type: 'detail-changed', finding: cur, previous: prev });
    } else {
      findingChanges.push({ type: 'unchanged', finding: cur });
    }
  }

  // Resolved: in baseline but not in current
  for (const [id, prev] of baselineMap) {
    if (!currentMap.has(id)) {
      findingChanges.push({ type: 'resolved', finding: prev });
    }
  }

  // Metric deltas — only emit when before !== after
  const metricDeltas: MetricDelta[] = [];
  for (const key of Object.keys(METRIC_META) as Array<keyof OrgMetrics>) {
    const before = baseline.metrics[key];
    const after  = current.metrics[key];
    if (before === after) continue;
    metricDeltas.push({
      key,
      label:     METRIC_META[key].label,
      before,
      after,
      delta:     after - before,
      direction: metricDirection(key, before, after),
    });
  }

  const gradeDelta =
    baseline.grade === current.grade
      ? 'unchanged'
      : `${baseline.grade} → ${current.grade}`;

  return {
    baseline,
    current,
    findingChanges,
    metricDeltas,
    scoreDelta: current.healthScore - baseline.healthScore,
    gradeDelta,
  };
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=DiffEngine`
Expected: PASS — all 12 assertions.

- [ ] **Step 5: Commit**

```bash
git add src/history/DiffEngine.ts test/unit/history/DiffEngine.test.ts
git commit -m "feat(history): add DiffEngine pure diff computation"
```

---

## Task 4: HistoryStore — Archive & Load

**Files:**
- Create: `src/history/HistoryStore.ts`
- Create: `test/unit/history/HistoryStore.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
// test/unit/history/HistoryStore.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { HistoryStore } from '../../../src/history/HistoryStore.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-audit-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('HistoryStore', () => {
  describe('archive', () => {
    it('writes a JSON file to {root}/{orgId}/', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult();
      store.archive(result);

      const orgDir = path.join(tmpDir, result.orgId);
      const files = fs.readdirSync(orgDir);
      expect(files).toHaveLength(1);
      expect(files[0]).toMatch(/^sf-audit-00D000000000001-\d+\.json$/);
    });

    it('stores valid JSON that round-trips to AuditResult', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult({ healthScore: 77, grade: 'C' });
      store.archive(result);

      const orgDir = path.join(tmpDir, result.orgId);
      const file = path.join(orgDir, fs.readdirSync(orgDir)[0]);
      const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
      expect(parsed.healthScore).toBe(77);
      expect(parsed.grade).toBe('C');
    });

    it('does not throw when the directory is read-only', () => {
      // Make tmpDir read-only so archive() cannot create subdirectory
      fs.chmodSync(tmpDir, 0o444);
      const store = new HistoryStore(tmpDir);
      expect(() => store.archive(makeResult())).not.toThrow();
      fs.chmodSync(tmpDir, 0o755); // restore so afterEach cleanup works
    });
  });

  describe('list', () => {
    it('returns results sorted oldest to newest', () => {
      const store = new HistoryStore(tmpDir);
      const older = makeResult({ generatedAt: new Date('2026-03-01T00:00:00Z'), healthScore: 50 });
      const newer = makeResult({ generatedAt: new Date('2026-04-01T00:00:00Z'), healthScore: 80 });
      store.archive(older);
      // Small delay between archives to get different timestamps in filenames
      store.archive(newer);

      const list = store.list('00D000000000001', tmpDir);
      expect(list).toHaveLength(2);
      expect(list[0].healthScore).toBe(50);
      expect(list[1].healthScore).toBe(80);
    });

    it('returns empty array when no reports exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(store.list('00DNONEXISTENT', tmpDir)).toEqual([]);
    });

    it('restores generatedAt as a Date object', () => {
      const store = new HistoryStore(tmpDir);
      store.archive(makeResult({ generatedAt: new Date('2026-03-01T12:00:00Z') }));
      const [loaded] = store.list('00D000000000001', tmpDir);
      expect(loaded.generatedAt).toBeInstanceOf(Date);
      expect(loaded.generatedAt.toISOString()).toBe('2026-03-01T12:00:00.000Z');
    });
  });

  describe('latest', () => {
    it('returns the most recent result', () => {
      const store = new HistoryStore(tmpDir);
      store.archive(makeResult({ generatedAt: new Date('2026-03-01T00:00:00Z'), healthScore: 50 }));
      store.archive(makeResult({ generatedAt: new Date('2026-04-01T00:00:00Z'), healthScore: 80 }));
      expect(store.latest('00D000000000001', tmpDir)?.healthScore).toBe(80);
    });

    it('returns null when no reports exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(store.latest('00DNONEXISTENT', tmpDir)).toBeNull();
    });
  });

  describe('load', () => {
    it('loads an arbitrary JSON file path', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult({ healthScore: 90, grade: 'A' });
      store.archive(result);
      const orgDir = path.join(tmpDir, result.orgId);
      const filePath = path.join(orgDir, fs.readdirSync(orgDir)[0]);

      const loaded = store.load(filePath);
      expect(loaded.healthScore).toBe(90);
      expect(loaded.generatedAt).toBeInstanceOf(Date);
    });

    it('throws when file does not exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(() => store.load('/nonexistent/path.json')).toThrow();
    });
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `npm test -- --testPathPattern=HistoryStore`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Implement HistoryStore**

```typescript
// src/history/HistoryStore.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AuditResult } from '../findings/AuditResult.js';

function parseResult(raw: string): AuditResult {
  const obj = JSON.parse(raw);
  obj.generatedAt = new Date(obj.generatedAt);
  return obj as AuditResult;
}

export class HistoryStore {
  private readonly root: string;

  constructor(root?: string) {
    this.root = root ?? HistoryStore.defaultRoot();
  }

  static defaultRoot(): string {
    return path.join(os.homedir(), '.sf', 'audit-history');
  }

  archive(result: AuditResult): void {
    try {
      const dir = path.join(this.root, result.orgId);
      fs.mkdirSync(dir, { recursive: true });
      const filename = `sf-audit-${result.orgId}-${Date.now()}.json`;
      fs.writeFileSync(path.join(dir, filename), JSON.stringify(result, null, 2), 'utf-8');
    } catch (err) {
      process.stderr.write(`[sf-audit] Warning: could not archive audit result: ${String(err)}\n`);
    }
  }

  list(orgId: string, dir?: string): AuditResult[] {
    const searchDir = dir ? path.join(dir, orgId) : path.join(this.root, orgId);
    if (!fs.existsSync(searchDir)) return [];

    const files = fs.readdirSync(searchDir)
      .filter((f) => f.startsWith('sf-audit-') && f.endsWith('.json'))
      .map((f) => path.join(searchDir, f));

    const results: AuditResult[] = [];
    for (const file of files) {
      try {
        results.push(parseResult(fs.readFileSync(file, 'utf-8')));
      } catch {
        // skip unparseable files silently
      }
    }

    return results.sort((a, b) => a.generatedAt.getTime() - b.generatedAt.getTime());
  }

  latest(orgId: string, dir?: string): AuditResult | null {
    const all = this.list(orgId, dir);
    return all.length > 0 ? all[all.length - 1] : null;
  }

  load(filePath: string): AuditResult {
    return parseResult(fs.readFileSync(filePath, 'utf-8'));
  }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=HistoryStore`
Expected: PASS — all assertions green.

- [ ] **Step 5: Commit**

```bash
git add src/history/HistoryStore.ts test/unit/history/HistoryStore.test.ts
git commit -m "feat(history): add HistoryStore archive/list/load"
```

---

## Task 5: DiffRenderer Interface + DiffJsonRenderer

**Files:**
- Create: `src/renderers/DiffRenderer.ts`
- Create: `src/renderers/DiffJsonRenderer.ts`
- Create: `test/unit/renderers/DiffJsonRenderer.test.ts`

- [ ] **Step 1: Create DiffRenderer interface**

```typescript
// src/renderers/DiffRenderer.ts
import type { AuditDiff } from '../history/AuditDiff.js';

export interface DiffRenderer {
  readonly format: string;
  readonly fileExtension: string;
  render(diff: AuditDiff): string;
}
```

- [ ] **Step 2: Write the failing test**

```typescript
// test/unit/renderers/DiffJsonRenderer.test.ts
import { DiffJsonRenderer } from '../../../src/renderers/DiffJsonRenderer.js';
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const BASELINE = makeResult({ healthScore: 64, grade: 'D' });
const CURRENT  = makeResult({ healthScore: 81, grade: 'B', generatedAt: new Date('2026-04-09T11:22:00Z') });

describe('DiffJsonRenderer', () => {
  const renderer = new DiffJsonRenderer();

  it('has format="json" and fileExtension=".json"', () => {
    expect(renderer.format).toBe('json');
    expect(renderer.fileExtension).toBe('.json');
  });

  it('produces valid JSON', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(() => JSON.parse(renderer.render(diff))).not.toThrow();
  });

  it('includes baseline, current, scoreDelta, gradeDelta, findingChanges, metricDeltas', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    const parsed = JSON.parse(renderer.render(diff));
    expect(parsed).toHaveProperty('baseline');
    expect(parsed).toHaveProperty('current');
    expect(parsed).toHaveProperty('scoreDelta', 17);
    expect(parsed).toHaveProperty('gradeDelta', 'D → B');
    expect(parsed).toHaveProperty('findingChanges');
    expect(parsed).toHaveProperty('metricDeltas');
  });
});
```

- [ ] **Step 3: Run test to confirm failure**

Run: `npm test -- --testPathPattern=DiffJsonRenderer`
Expected: FAIL — "Cannot find module"

- [ ] **Step 4: Implement DiffJsonRenderer**

```typescript
// src/renderers/DiffJsonRenderer.ts
import type { AuditDiff } from '../history/AuditDiff.js';
import type { DiffRenderer } from './DiffRenderer.js';

export class DiffJsonRenderer implements DiffRenderer {
  readonly format = 'json';
  readonly fileExtension = '.json';

  render(diff: AuditDiff): string {
    return JSON.stringify(diff, null, 2);
  }
}
```

- [ ] **Step 5: Run test to confirm pass**

Run: `npm test -- --testPathPattern=DiffJsonRenderer`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/renderers/DiffRenderer.ts src/renderers/DiffJsonRenderer.ts test/unit/renderers/DiffJsonRenderer.test.ts
git commit -m "feat(history): add DiffRenderer interface and DiffJsonRenderer"
```

---

## Task 6: DiffHtmlRenderer

**Files:**
- Create: `src/renderers/DiffHtmlRenderer.ts`
- Create: `test/unit/renderers/DiffHtmlRenderer.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// test/unit/renderers/DiffHtmlRenderer.test.ts
import { DiffHtmlRenderer } from '../../../src/renderers/DiffHtmlRenderer.js';
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const BASELINE = makeResult({
  healthScore: 64,
  grade: 'D',
  findings: [
    { id: 'f-resolved', checkId: 'c1', category: 'Auth', riskLevel: 'HIGH', title: 'Old finding', detail: 'detail', remediation: 'fix' },
    { id: 'f-new-base', checkId: 'c2', category: 'Auth', riskLevel: 'LOW',  title: 'Stays',       detail: 'detail', remediation: 'fix' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 5 },
});

const CURRENT = makeResult({
  healthScore: 81,
  grade: 'B',
  generatedAt: new Date('2026-04-09T11:22:00Z'),
  findings: [
    { id: 'f-new-cur',  checkId: 'c3', category: 'Auth', riskLevel: 'CRITICAL', title: 'New one',  detail: 'detail', remediation: 'fix' },
    { id: 'f-new-base', checkId: 'c2', category: 'Auth', riskLevel: 'LOW',       title: 'Stays',   detail: 'detail', remediation: 'fix' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 3 },
});

describe('DiffHtmlRenderer', () => {
  const renderer = new DiffHtmlRenderer();

  it('has format="html" and fileExtension=".html"', () => {
    expect(renderer.format).toBe('html');
    expect(renderer.fileExtension).toBe('.html');
  });

  it('produces a valid HTML document', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    const html = renderer.render(diff);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });

  it('includes org name in the output', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Test Org');
  });

  it('includes score delta', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('+17');
  });

  it('includes grade delta', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('D → B');
  });

  it('shows new finding title', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('New one');
  });

  it('shows resolved finding title', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Old finding');
  });

  it('includes metric delta label', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Modify All Data Users');
  });
});
```

- [ ] **Step 2: Run test to confirm failure**

Run: `npm test -- --testPathPattern=DiffHtmlRenderer`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Implement DiffHtmlRenderer**

```typescript
// src/renderers/DiffHtmlRenderer.ts
import type { AuditDiff, FindingChange } from '../history/AuditDiff.js';
import type { DiffRenderer } from './DiffRenderer.js';

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(d: Date): string {
  return d.toISOString().replace('T', ' ').substring(0, 16);
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#64748b',
};

const CHANGE_LABELS: Record<string, string> = {
  'new': 'New', 'resolved': 'Resolved', 'severity-changed': 'Severity Changed', 'detail-changed': 'Detail Changed',
};

function renderFindingCard(change: FindingChange): string {
  const f = change.finding;
  const typeColor = change.type === 'new' ? '#dc2626' : change.type === 'resolved' ? '#22c55e' : '#d97706';
  const prevBadge = change.previous
    ? `<span class="risk-badge" style="background:${RISK_COLORS[change.previous.riskLevel] ?? '#64748b'}">${esc(change.previous.riskLevel)}</span> → `
    : '';

  return `
  <div class="finding-card" style="border-left-color:${typeColor}">
    <div class="finding-header">
      <span class="change-badge" style="background:${typeColor}">${CHANGE_LABELS[change.type] ?? change.type}</span>
      ${prevBadge}<span class="risk-badge" style="background:${RISK_COLORS[f.riskLevel] ?? '#64748b'}">${esc(f.riskLevel)}</span>
      <span class="finding-title">${esc(f.title)}</span>
      <span class="finding-category">${esc(f.category)}</span>
    </div>
    ${change.type === 'detail-changed' && change.previous ? `
    <div class="detail-diff">
      <div class="diff-before"><strong>Before:</strong> ${esc(change.previous.detail)}</div>
      <div class="diff-after"><strong>After:</strong> ${esc(f.detail)}</div>
    </div>` : ''}
  </div>`;
}

export class DiffHtmlRenderer implements DiffRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  render(diff: AuditDiff): string {
    const { baseline, current } = diff;
    const scoreDeltaStr = diff.scoreDelta >= 0 ? `+${diff.scoreDelta}` : `${diff.scoreDelta}`;
    const scoreDeltaColor = diff.scoreDelta > 0 ? '#22c55e' : diff.scoreDelta < 0 ? '#dc2626' : '#8b949e';

    const changeCounts = {
      new:               diff.findingChanges.filter((c) => c.type === 'new').length,
      resolved:          diff.findingChanges.filter((c) => c.type === 'resolved').length,
      'severity-changed':diff.findingChanges.filter((c) => c.type === 'severity-changed').length,
      'detail-changed':  diff.findingChanges.filter((c) => c.type === 'detail-changed').length,
    };

    const sectionOrder: Array<FindingChange['type']> = ['new', 'resolved', 'severity-changed', 'detail-changed', 'unchanged'];
    const sections = sectionOrder.map((type) => {
      const changes = diff.findingChanges.filter((c) => c.type === type);
      if (changes.length === 0) return '';
      const sectionClass = type === 'unchanged' ? ' class="unchanged-section"' : '';
      return `
  <section${sectionClass}>
    <h2>${CHANGE_LABELS[type] ?? type} (${changes.length})</h2>
    ${changes.map(renderFindingCard).join('')}
  </section>`;
    }).join('');

    const metricRows = diff.metricDeltas.map((d) => {
      const color = d.direction === 'improved' ? '#22c55e' : d.direction === 'degraded' ? '#dc2626' : '#8b949e';
      const arrow = d.delta > 0 ? '▲' : '▼';
      const deltaStr = d.delta > 0 ? `+${d.delta}` : `${d.delta}`;
      return `<tr>
        <td>${esc(d.label)}</td>
        <td style="text-align:right">${d.before}</td>
        <td style="text-align:right">${d.after}</td>
        <td style="text-align:right;color:${color};font-weight:700">${arrow} ${deltaStr}</td>
      </tr>`;
    }).join('');

    const metricsSection = diff.metricDeltas.length > 0 ? `
  <section>
    <h2>Metric Changes</h2>
    <table class="metric-table">
      <thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
      <tbody>${metricRows}</tbody>
    </table>
  </section>` : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Audit Diff — ${esc(baseline.orgName)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; max-width: 1000px; margin: 2rem auto; padding: 0 1.25rem 4rem; line-height: 1.6; }
  h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  h2 { color: #e6edf3; font-size: 1.1rem; font-weight: 700; margin: 1.5rem 0 0.75rem; }
  .meta { font-size: 0.8rem; color: #8b949e; display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; margin-bottom: 1.5rem; }
  .scorecard { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.25rem 2rem; display: flex; gap: 2rem; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .score-delta { font-size: 2.5rem; font-weight: 800; color: ${scoreDeltaColor}; line-height: 1; }
  .grade-delta { font-size: 1.2rem; font-weight: 700; color: #c9d1d9; }
  .summary-counts { display: flex; gap: 1rem; flex-wrap: wrap; }
  .count-badge { background: #1c2128; border: 1px solid #30363d; border-radius: 8px; padding: 0.5rem 1rem; text-align: center; }
  .count-badge .num { font-size: 1.5rem; font-weight: 800; display: block; }
  .count-badge .lbl { font-size: 0.75rem; color: #8b949e; }
  .finding-card { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #30363d; border-radius: 8px; margin-bottom: 0.5rem; padding: 0.75rem 1rem; }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .change-badge { padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 800; color: #fff; letter-spacing: 0.04em; }
  .risk-badge { padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 800; color: #fff; }
  .finding-title { flex: 1; font-weight: 600; color: #e6edf3; font-size: 0.9rem; }
  .finding-category { font-size: 0.75rem; color: #8b949e; }
  .detail-diff { margin-top: 0.5rem; font-size: 0.82rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
  .diff-before { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); border-radius: 4px; padding: 0.5rem; }
  .diff-after  { background: rgba(34,197,94,0.1);  border: 1px solid rgba(34,197,94,0.3);  border-radius: 4px; padding: 0.5rem; }
  .unchanged-section { opacity: 0.5; }
  .metric-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  .metric-table th { background: #1c2128; color: #8b949e; text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #30363d; font-weight: 600; }
  .metric-table td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; }
  .metric-table tr:last-child td { border-bottom: none; }
  section { margin-bottom: 2rem; }
</style>
</head>
<body>
  <h1>Salesforce Audit Diff</h1>
  <div class="meta">
    <span>Org: <strong style="color:#c9d1d9">${esc(baseline.orgName)}</strong> (${esc(baseline.orgId)})</span>
    <span>Baseline: ${fmtDate(baseline.generatedAt)}</span>
    <span>Current: ${fmtDate(current.generatedAt)}</span>
  </div>

  <div class="scorecard">
    <div>
      <div class="score-delta">${scoreDeltaStr}</div>
      <div style="font-size:0.8rem;color:#8b949e;margin-top:0.25rem">score change</div>
    </div>
    <div class="grade-delta">${esc(diff.gradeDelta)}</div>
    <div class="summary-counts">
      <div class="count-badge"><span class="num" style="color:#dc2626">${changeCounts.new}</span><span class="lbl">New</span></div>
      <div class="count-badge"><span class="num" style="color:#22c55e">${changeCounts.resolved}</span><span class="lbl">Resolved</span></div>
      <div class="count-badge"><span class="num" style="color:#d97706">${changeCounts['severity-changed']}</span><span class="lbl">Sev. Changed</span></div>
      <div class="count-badge"><span class="num" style="color:#64748b">${changeCounts['detail-changed']}</span><span class="lbl">Detail Changed</span></div>
    </div>
  </div>

  ${metricsSection}
  ${sections}

<script>
  // Toggle unchanged findings visibility
  const unchanged = document.querySelector('.unchanged-section');
  if (unchanged) {
    const toggle = document.createElement('button');
    toggle.textContent = 'Show Unchanged';
    toggle.style.cssText = 'background:#1c2128;border:1px solid #30363d;color:#8b949e;padding:0.3rem 0.75rem;border-radius:20px;cursor:pointer;font-size:0.8rem;margin-bottom:0.75rem';
    unchanged.insertBefore(toggle, unchanged.querySelector('h2')!.nextSibling);
    let visible = false;
    unchanged.querySelectorAll('.finding-card').forEach(c => (c as HTMLElement).style.display = 'none');
    toggle.addEventListener('click', () => {
      visible = !visible;
      toggle.textContent = visible ? 'Hide Unchanged' : 'Show Unchanged';
      unchanged.querySelectorAll('.finding-card').forEach(c => (c as HTMLElement).style.display = visible ? '' : 'none');
    });
  }
</script>
</body>
</html>`;
  }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=DiffHtmlRenderer`
Expected: PASS — all 8 assertions.

- [ ] **Step 5: Commit**

```bash
git add src/renderers/DiffHtmlRenderer.ts test/unit/renderers/DiffHtmlRenderer.test.ts
git commit -m "feat(history): add DiffHtmlRenderer"
```

---

## Task 7: HistoryRenderer — Terminal Table + HTML Timeline

**Files:**
- Create: `src/renderers/HistoryRenderer.ts`
- Create: `test/unit/renderers/HistoryRenderer.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// test/unit/renderers/HistoryRenderer.test.ts
import { HistoryRenderer } from '../../../src/renderers/HistoryRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const R1 = makeResult({ generatedAt: new Date('2026-03-23T15:10:00Z'), healthScore: 64, grade: 'D', findings: [{ id: 'f1', checkId: 'c1', category: 'Auth', riskLevel: 'CRITICAL', title: 'T', detail: 'd', remediation: 'r' }] });
const R2 = makeResult({ generatedAt: new Date('2026-04-09T11:22:00Z'), healthScore: 81, grade: 'B', findings: [] });

describe('HistoryRenderer', () => {
  const renderer = new HistoryRenderer();

  describe('renderTable', () => {
    it('includes org name in header', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('Test Org');
    });

    it('shows score for each run', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('64');
      expect(table).toContain('81');
    });

    it('shows delta score from second run onward', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('+17');
    });

    it('shows — for first run delta', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('—');
    });

    it('includes trend summary line', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('Trend');
    });

    it('shows finding counts per severity', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('1'); // R1 has 1 CRITICAL
    });
  });

  describe('renderHtml', () => {
    it('produces a valid HTML document with Chart.js', () => {
      const html = renderer.renderHtml([R1, R2]);
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('chart.js');
    });

    it('includes org name', () => {
      expect(renderer.renderHtml([R1, R2])).toContain('Test Org');
    });

    it('embeds health scores as Chart.js data', () => {
      const html = renderer.renderHtml([R1, R2]);
      expect(html).toContain('64');
      expect(html).toContain('81');
    });
  });
});
```

- [ ] **Step 2: Run test to confirm failure**

Run: `npm test -- --testPathPattern=HistoryRenderer`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Implement HistoryRenderer**

```typescript
// src/renderers/HistoryRenderer.ts
import type { AuditResult } from '../findings/AuditResult.js';

function fmtDate(d: Date): string {
  return d.toISOString().replace('T', ' ').substring(0, 16);
}

function countBySeverity(result: AuditResult, level: string): number {
  return result.findings.filter((f) => f.riskLevel === level).length;
}

export class HistoryRenderer {

  renderTable(results: AuditResult[]): string {
    if (results.length === 0) return 'No audit history found.';

    const orgName = results[0].orgName;
    const orgId   = results[0].orgId;

    const header = `Audit History: ${orgName} (${orgId})`;
    const divider = '─'.repeat(Math.max(header.length, 80));
    const colHeader = '  #   Date                  Score   Grade   CRIT   HIGH    MED    LOW   Δ Score';

    const rows = results.map((r, i) => {
      const prev  = i > 0 ? results[i - 1] : null;
      const delta = prev ? (r.healthScore - prev.healthScore >= 0 ? `+${r.healthScore - prev.healthScore}` : `${r.healthScore - prev.healthScore}`) : '—';
      const crit = String(countBySeverity(r, 'CRITICAL')).padStart(4);
      const high = String(countBySeverity(r, 'HIGH')).padStart(4);
      const med  = String(countBySeverity(r, 'MEDIUM')).padStart(6);
      const low  = String(countBySeverity(r, 'LOW')).padStart(6);
      return `  ${String(i + 1).padStart(2)}  ${fmtDate(r.generatedAt).padEnd(20)} ${String(r.healthScore).padStart(5)}   ${r.grade.padEnd(5)} ${crit}   ${high}  ${med}  ${low}  ${String(delta).padStart(7)}`;
    });

    const scores = results.map((r) => r.healthScore);
    const best   = Math.max(...scores);
    const worst  = Math.min(...scores);
    const trend  = scores[scores.length - 1] - scores[0];
    const trendStr = trend >= 0 ? `▲ +${trend}` : `▼ ${trend}`;
    const bestDate  = fmtDate(results[scores.indexOf(best)].generatedAt);
    const worstDate = fmtDate(results[scores.indexOf(worst)].generatedAt);
    const summary = `  Trend: ${trendStr} over ${results.length} audit${results.length !== 1 ? 's' : ''}   Best: ${best} (${bestDate})   Worst: ${worst} (${worstDate})`;

    return [header, divider, colHeader, divider, ...rows, divider, summary].join('\n');
  }

  renderHtml(results: AuditResult[]): string {
    if (results.length === 0) return '<!DOCTYPE html><html><body><p>No audit history found.</p></body></html>';

    const orgName = results[0].orgName;
    const orgId   = results[0].orgId;

    const labels   = JSON.stringify(results.map((r) => fmtDate(r.generatedAt)));
    const scores   = JSON.stringify(results.map((r) => r.healthScore));
    const crits    = JSON.stringify(results.map((r) => countBySeverity(r, 'CRITICAL')));
    const highs    = JSON.stringify(results.map((r) => countBySeverity(r, 'HIGH')));
    const meds     = JSON.stringify(results.map((r) => countBySeverity(r, 'MEDIUM')));
    const lows     = JSON.stringify(results.map((r) => countBySeverity(r, 'LOW')));

    const tableRows = results.map((r, i) => {
      const prev  = i > 0 ? results[i - 1] : null;
      const delta = prev ? (r.healthScore - prev.healthScore >= 0 ? `+${r.healthScore - prev.healthScore}` : `${r.healthScore - prev.healthScore}`) : '—';
      const deltaColor = prev ? (r.healthScore >= prev.healthScore ? '#22c55e' : '#dc2626') : '#8b949e';
      return `<tr>
        <td>${i + 1}</td>
        <td>${fmtDate(r.generatedAt)}</td>
        <td style="text-align:right;font-weight:700">${r.healthScore}</td>
        <td style="text-align:center">${r.grade}</td>
        <td style="text-align:right;color:#dc2626">${countBySeverity(r, 'CRITICAL')}</td>
        <td style="text-align:right;color:#ea580c">${countBySeverity(r, 'HIGH')}</td>
        <td style="text-align:right;color:#d97706">${countBySeverity(r, 'MEDIUM')}</td>
        <td style="text-align:right;color:#2563eb">${countBySeverity(r, 'LOW')}</td>
        <td style="text-align:right;color:${deltaColor};font-weight:700">${delta}</td>
      </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Audit History — ${orgName}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; max-width: 1100px; margin: 2rem auto; padding: 0 1.25rem 4rem; line-height: 1.6; }
  h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  h2 { color: #e6edf3; font-size: 1.1rem; font-weight: 700; margin: 2rem 0 1rem; }
  .meta { font-size: 0.8rem; color: #8b949e; margin-bottom: 2rem; }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
  .chart-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.25rem; }
  canvas { max-height: 280px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { background: #1c2128; color: #8b949e; text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #30363d; font-weight: 600; }
  td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  @media(max-width:640px) { .charts { grid-template-columns: 1fr; } }
</style>
</head>
<body>
  <h1>Salesforce Audit History</h1>
  <div class="meta">Org: <strong style="color:#c9d1d9">${orgName}</strong> (${orgId})</div>

  <div class="charts">
    <div class="chart-box">
      <h2>Score Trend</h2>
      <canvas id="scoreChart"></canvas>
    </div>
    <div class="chart-box">
      <h2>Findings by Severity</h2>
      <canvas id="findingsChart"></canvas>
    </div>
  </div>

  <h2>Run History</h2>
  <table>
    <thead><tr><th>#</th><th>Date</th><th style="text-align:right">Score</th><th style="text-align:center">Grade</th><th style="text-align:right">CRIT</th><th style="text-align:right">HIGH</th><th style="text-align:right">MED</th><th style="text-align:right">LOW</th><th style="text-align:right">Δ Score</th></tr></thead>
    <tbody>${tableRows}</tbody>
  </table>

<script>
const labels = ${labels};
const scores = ${scores};
const crits  = ${crits};
const highs  = ${highs};
const meds   = ${meds};
const lows   = ${lows};

const chartDefaults = { responsive: true, plugins: { legend: { labels: { color: '#8b949e' } } }, scales: { x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }, y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } } } };

new Chart(document.getElementById('scoreChart'), {
  type: 'line',
  data: { labels, datasets: [{ label: 'Health Score', data: scores, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.1)', tension: 0.3, fill: true, pointRadius: 4 }] },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 100 } } },
});

new Chart(document.getElementById('findingsChart'), {
  type: 'bar',
  data: {
    labels,
    datasets: [
      { label: 'CRITICAL', data: crits, backgroundColor: '#dc2626' },
      { label: 'HIGH',     data: highs, backgroundColor: '#ea580c' },
      { label: 'MEDIUM',   data: meds,  backgroundColor: '#d97706' },
      { label: 'LOW',      data: lows,  backgroundColor: '#2563eb' },
    ],
  },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, x: { ...chartDefaults.scales.x, stacked: true }, y: { ...chartDefaults.scales.y, stacked: true } } },
});
</script>
</body>
</html>`;
  }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=HistoryRenderer`
Expected: PASS — all assertions green.

- [ ] **Step 5: Commit**

```bash
git add src/renderers/HistoryRenderer.ts test/unit/renderers/HistoryRenderer.test.ts
git commit -m "feat(history): add HistoryRenderer terminal table and HTML timeline"
```

---

## Task 8: `sf audit diff` Command

**Files:**
- Create: `src/commands/audit/diff.ts`

No unit tests for the command itself — it wires together already-tested components. Tested by building and running manually.

- [ ] **Step 1: Create the command**

```typescript
// src/commands/audit/diff.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { HistoryStore } from '../../history/HistoryStore.js';
import { computeDiff } from '../../history/DiffEngine.js';
import { DiffHtmlRenderer } from '../../renderers/DiffHtmlRenderer.js';
import { DiffJsonRenderer } from '../../renderers/DiffJsonRenderer.js';
import type { DiffRenderer } from '../../renderers/DiffRenderer.js';
import type { AuditDiff } from '../../history/AuditDiff.js';

const DIFF_RENDERERS: Record<string, DiffRenderer> = {
  html: new DiffHtmlRenderer(),
  json: new DiffJsonRenderer(),
};

export default class AuditDiffCommand extends SfCommand<AuditDiff> {
  public static summary = 'Compare two audit report JSON files and show what changed';
  public static description =
    'Loads two audit report JSON files, computes the diff, and writes HTML and/or JSON diff reports.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> baseline.json current.json',
    '<%= config.bin %> <%= command.id %> baseline.json current.json --output ./reports --format html',
  ];

  public static args = {
    baseline: { name: 'baseline', required: true, description: 'Path to the baseline (older) audit JSON report' },
    current:  { name: 'current',  required: true, description: 'Path to the current (newer) audit JSON report' },
  };

  public static flags = {
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write diff reports. Defaults to current directory.',
      default: '.',
    }),
    format: Flags.string({
      char: 'f',
      summary: 'Output format(s), comma-separated: html, json',
      default: 'html,json',
    }),
  };

  public async run(): Promise<AuditDiff> {
    const { args, flags } = await this.parse(AuditDiffCommand);

    const store    = new HistoryStore();
    const baseline = store.load(args['baseline'] as string);
    const current  = store.load(args['current'] as string);

    if (baseline.orgId !== current.orgId) {
      this.warn(`Org IDs differ: baseline=${baseline.orgId}, current=${current.orgId}. Continuing anyway.`);
    }

    const diff    = computeDiff(baseline, current);
    const formats = flags.format.split(',').map((f) => f.trim());
    const baseTs  = baseline.generatedAt.getTime();
    const curTs   = current.generatedAt.getTime();

    for (const format of formats) {
      const renderer = DIFF_RENDERERS[format];
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, json`);
        continue;
      }
      const filename   = `sf-audit-diff-${baseline.orgId}-${baseTs}-vs-${curTs}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, renderer.render(diff), 'utf-8');
      this.log(`Diff report written: ${outputPath}`);
    }

    const scoreDeltaStr  = diff.scoreDelta >= 0 ? `+${diff.scoreDelta}` : `${diff.scoreDelta}`;
    const newCount       = diff.findingChanges.filter((c) => c.type === 'new').length;
    const resolvedCount  = diff.findingChanges.filter((c) => c.type === 'resolved').length;
    this.log('');
    this.log('─────────────────────────────');
    this.log('  Diff Summary');
    this.log('─────────────────────────────');
    this.log(`  Score delta  ${scoreDeltaStr.padStart(6)}`);
    this.log(`  Grade        ${diff.gradeDelta}`);
    this.log(`  New          ${String(newCount).padStart(6)}`);
    this.log(`  Resolved     ${String(resolvedCount).padStart(6)}`);
    this.log('─────────────────────────────');

    return diff;
  }
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `npm run build`
Expected: exit 0, no TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add src/commands/audit/diff.ts
git commit -m "feat(history): add sf audit diff command"
```

---

## Task 9: `sf audit history` Command

**Files:**
- Create: `src/commands/audit/history.ts`

- [ ] **Step 1: Create the command**

```typescript
// src/commands/audit/history.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { HistoryStore } from '../../history/HistoryStore.js';
import { HistoryRenderer } from '../../renderers/HistoryRenderer.js';
import type { AuditResult } from '../../findings/AuditResult.js';

export default class AuditHistoryCommand extends SfCommand<AuditResult[]> {
  public static summary = 'Show audit history for an org';
  public static description =
    'Scans archived audit reports for the target org, prints a terminal table, and writes an HTML timeline.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --reports-dir ./reports --limit 10',
  ];

  public static flags = {
    'target-org':   Flags.requiredOrg(),
    'reports-dir':  Flags.string({
      summary: 'Directory containing archived report files. Defaults to ~/.sf/audit-history/{orgId}.',
      helpValue: './reports',
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the HTML timeline. Defaults to current directory.',
      default: '.',
    }),
    limit: Flags.integer({
      summary: 'Maximum number of most-recent runs to include.',
      helpValue: '20',
    }),
  };

  public async run(): Promise<AuditResult[]> {
    const { flags } = await this.parse(AuditHistoryCommand);

    const orgId    = flags['target-org'].getOrgId();
    const store    = new HistoryStore();
    const reportsDir = flags['reports-dir'];

    let results = store.list(orgId, reportsDir);

    if (results.length < 2) {
      if (results.length === 0) {
        this.log(`No audit history found for org ${orgId}.`);
        this.log(`Run 'sf audit security --target-org <alias>' to create the first report.`);
      } else {
        this.log(`Only 1 audit run found for org ${orgId}. Run at least 2 audits to see trends.`);
      }
      return results;
    }

    if (flags.limit !== undefined) {
      results = results.slice(-flags.limit);
    }

    const renderer = new HistoryRenderer();
    this.log(renderer.renderTable(results));

    const filename   = `sf-audit-history-${orgId}-${Date.now()}.html`;
    const outputPath = path.join(flags.output, filename);
    fs.writeFileSync(outputPath, renderer.renderHtml(results), 'utf-8');
    this.log(`\nHistory report written: ${outputPath}`);

    return results;
  }
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `npm run build`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/commands/audit/history.ts
git commit -m "feat(history): add sf audit history command"
```

---

## Task 10: Wire Auto-Archive into `security.ts` + Export Types from `index.ts`

**Files:**
- Modify: `src/commands/audit/security.ts`
- Modify: `src/index.ts`

- [ ] **Step 1: Add auto-archive to security.ts**

In `src/commands/audit/security.ts`, add the import at the top (after the existing imports):

```typescript
import { HistoryStore } from '../../history/HistoryStore.js';
```

Then add these 3 lines after the renderers loop (after `this.log('');` before `this.printSummary(result);`). The exact location is after line `this.log(\`\nReport written: ${outputPath}\`);` inside the `for` loop, and after the loop closes. Insert between the closing brace of the formats loop and `this.log('')`:

```typescript
    // Auto-archive: silently save a copy for history tracking
    const store = new HistoryStore();
    store.archive(result);
```

The modified section looks like this:

```typescript
    const formats = flags.format.split(',').map((f) => f.trim());
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

    // Auto-archive: silently save a copy for history tracking
    const store = new HistoryStore();
    store.archive(result);

    this.log('');
    this.printSummary(result);
```

- [ ] **Step 2: Update index.ts to export public types**

Replace the contents of `src/index.ts`:

```typescript
// Plugin entry point — oclif discovers commands from lib/commands/ automatically
export type { AuditResult } from './findings/AuditResult.js';
export type { Finding, AffectedItem } from './findings/Finding.js';
export type { RiskLevel } from './findings/RiskLevel.js';
export type { OrgMetrics } from './context/OrgMetrics.js';
export type { AuditDiff, FindingChange, FindingChangeType, MetricDelta } from './history/AuditDiff.js';
export { HistoryStore } from './history/HistoryStore.js';
export { computeDiff } from './history/DiffEngine.js';
```

- [ ] **Step 3: Build to verify everything compiles**

Run: `npm run build`
Expected: exit 0, no TypeScript errors.

- [ ] **Step 4: Run all tests**

Run: `npm test`
Expected: all existing tests still PASS (we didn't break anything), new tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/commands/audit/security.ts src/index.ts
git commit -m "feat(history): wire auto-archive into security command, export public types"
```

---

## Task 11: README Updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the existing README to find the right insertion point**

Open `README.md` and find the section after the existing commands documentation (after the `sf audit list` section or near the end of the commands section).

- [ ] **Step 2: Add the History & Diff section**

Add the following section after the existing commands documentation:

```markdown
## History & Diff

Every `sf audit security` run automatically archives a JSON copy of the report to:

```
~/.sf/audit-history/{orgId}/sf-audit-{orgId}-{timestamp}.json
```

No configuration needed — archiving happens silently after each run.

### View Audit History

Show how your org's security posture has changed across multiple runs:

```bash
sf audit history --target-org myOrg
```

Prints a terminal table with score trends and writes an HTML timeline to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--reports-dir` | Custom directory containing archived reports | `~/.sf/audit-history/{orgId}` |
| `--output` | Directory to write the HTML timeline | `.` (cwd) |
| `--limit` | Maximum number of most-recent runs to show | all |

**Example output:**

```
Audit History: My Org (00D000000000001)
────────────────────────────────────────────────────────────────────────────────
  #   Date                  Score   Grade   CRIT   HIGH    MED    LOW   Δ Score
────────────────────────────────────────────────────────────────────────────────
   1  2026-03-23 15:10       64      D          1      5      8      3        —
   2  2026-04-09 11:22       81      B          0      2      5      3      +17
────────────────────────────────────────────────────────────────────────────────
  Trend: ▲ +17 over 2 audits   Best: 81 (2026-04-09 11:22)   Worst: 64 (2026-03-23 15:10)
```

### Diff Two Reports

Compare any two audit JSON files to see exactly what changed:

```bash
sf audit diff baseline.json current.json
```

Writes an HTML and JSON diff report to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--output` | Directory to write diff reports | `.` (cwd) |
| `--format` | Comma-separated formats: `html`, `json` | `html,json` |

**Example output:**

```
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....html
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....json

─────────────────────────────
  Diff Summary
─────────────────────────────
  Score delta     +17
  Grade        D → B
  New               0
  Resolved          1
─────────────────────────────
```
```

- [ ] **Step 3: Build and run all tests one final time**

Run: `npm run build && npm test`
Expected: exit 0, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add History & Diff section to README"
```

---

## Self-Review Checklist

Spec sections checked against plan tasks:

| Spec Section | Covered By |
|---|---|
| Auto-archive to `~/.sf/audit-history/{orgId}/` | Task 4 (HistoryStore), Task 10 (security.ts wire-up) |
| `sf audit diff <baseline> <current>` | Task 8 |
| `--format html,json` on diff | Task 5, 6, 8 |
| `sf audit history --target-org` | Task 9 |
| `--reports-dir` flag | Task 4 (list), Task 9 |
| `--limit` flag | Task 9 |
| `HistoryStore.archive()` silent on failure | Task 4 |
| `HistoryStore.list()` sorted oldest→newest | Task 4 |
| `HistoryStore.load()` for arbitrary JSON file | Task 4 |
| `AuditDiff` types | Task 1 |
| `metricMeta.ts` direction lookup | Task 2 |
| `computeDiff()` all 5 change types | Task 3 |
| Metric deltas only where before ≠ after | Task 3 |
| `direction` per metric | Task 2, 3 |
| `DiffHtmlRenderer` — unchanged togglable | Task 6 |
| `HistoryRenderer` terminal table | Task 7 |
| `HistoryRenderer` HTML timeline with Chart.js | Task 7 |
| Filename patterns | Task 8, 9 |
| Warn if orgIds differ in diff command | Task 8 |
| README History & Diff section | Task 11 |
| Export public types from `index.ts` | Task 10 |
| `gradeDelta` "unchanged" when equal | Task 3 tests |
| Fewer than 2 runs: helpful message | Task 9 |
| `DiffHtmlRenderer` consistent dark theme | Task 6 |

All spec requirements are covered. No placeholders found. Types are consistent across tasks (`FindingChange`, `MetricDelta`, `AuditDiff` defined in Task 1 and used consistently in Tasks 3–8).
