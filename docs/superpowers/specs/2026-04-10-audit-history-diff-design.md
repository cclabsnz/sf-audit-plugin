# Audit History & Diff — Architecture Design

**Date:** 2026-04-10               
**Project:** `@cclabsnz/sf-audit`
**Status:** Approved design — ready for implementation planning

---

## Goal

Add time series analysis and change tracking to the SF audit CLI plugin. Users can see how their org's security posture has evolved across multiple audit runs, and diff any two reports to understand exactly what changed.

Three capabilities:

1. **Auto-archive** — every `sf audit security` run silently saves a JSON copy to `~/.sf/audit-history/{orgId}/`
2. **`sf audit diff`** — compare two report files; writes an HTML + JSON diff report
3. **`sf audit history`** — scan past reports for an org; shows a terminal table and writes an HTML timeline with charts

---

## Architectural Approach: Shared Service Layer (Option B)

New code follows the existing layered pattern exactly: domain model → pure computation → renderers → thin command wires. The existing `CheckEngine`, all 23 checks, `QueryRegistry`, and all existing renderers are untouched. Only two existing files gain new lines.

---

## New Files

```
src/
  history/
    HistoryStore.ts       ← file I/O for the archive store
    AuditDiff.ts          ← FindingChange, MetricDelta, AuditDiff types
    DiffEngine.ts         ← computeDiff() pure function
    metricMeta.ts         ← direction lookup + human labels for OrgMetrics keys
  renderers/
    DiffRenderer.ts       ← DiffRenderer interface
    DiffHtmlRenderer.ts   ← HTML diff report
    DiffJsonRenderer.ts   ← JSON diff report
    HistoryRenderer.ts    ← terminal table + HTML timeline
  commands/
    audit/
      diff.ts             ← sf audit diff <baseline> <current>
      history.ts          ← sf audit history --target-org <alias>
```

**Changed existing files:**

- `src/commands/audit/security.ts` — +3 lines: archive result after renderers loop
- `src/index.ts` — export new public types

---

## 1. Archive Subsystem (`HistoryStore`)

Archive path: `~/.sf/audit-history/{orgId}/sf-audit-{orgId}-{timestamp}.json`

```typescript
export class HistoryStore {
  constructor(root?: string)  // defaults to ~/.sf/audit-history

  static defaultRoot(): string
  archive(result: AuditResult): void         // silent — warns on failure, never throws
  list(orgId: string, dir?: string): AuditResult[]  // sorted oldest→newest
  latest(orgId: string, dir?: string): AuditResult | null
  load(filePath: string): AuditResult        // for diff command — loads any JSON report file
}
```

`list()` scans `{root}/{orgId}/sf-audit-*.json` (or `--reports-dir` if provided), parses each, sorts by `generatedAt`. `archive()` is fire-and-forget — if it fails (permissions, disk), it logs a warning but does not fail the audit run.

**Change to `security.ts`:**
```typescript
// After renderers loop
const store = new HistoryStore();
store.archive(result);  // silent — warns on failure, never throws
```

---

## 2. `AuditDiff` Domain Model

```typescript
export type FindingChangeType =
  | 'new'
  | 'resolved'
  | 'severity-changed'
  | 'detail-changed'
  | 'unchanged';

export interface FindingChange {
  type: FindingChangeType;
  finding: Finding;     // current (or resolved) finding
  previous?: Finding;   // populated for severity-changed and detail-changed
}

export interface MetricDelta {
  key: keyof OrgMetrics;
  label: string;        // human-readable: "Total Active Users"
  before: number;
  after: number;
  delta: number;        // after - before
  direction: 'improved' | 'degraded' | 'neutral';  // context-aware (see metricMeta.ts)
}

export interface AuditDiff {
  baseline: AuditResult;
  current: AuditResult;
  findingChanges: FindingChange[];
  metricDeltas: MetricDelta[];     // only rows where before !== after
  scoreDelta: number;              // current.healthScore - baseline.healthScore
  gradeDelta: string;              // "C → B" or "unchanged"
}
```

Finding key: `finding.id`. Change classification:
- `new` — in current, not in baseline
- `resolved` — in baseline, not in current
- `severity-changed` — in both, `riskLevel` differs
- `detail-changed` — in both, same `riskLevel`, but `detail`, `remediation`, or `affectedItems` differs
- `unchanged` — in both, nothing differs

`direction` on `MetricDelta` is driven by `metricMeta.ts` — a static lookup table. Examples: `modifyAllDataUsersCount` up = `degraded`; `codeCoveragePercent` up = `improved`; `totalActiveUsers` = `neutral`.

---

## 3. `DiffEngine`

Pure, stateless function — no I/O, no side effects, independently unit-testable.

```typescript
export function computeDiff(baseline: AuditResult, current: AuditResult): AuditDiff
```

Implementation:
1. Build `Map<id, Finding>` for baseline and current
2. Walk current map: classify each finding against baseline
3. Walk baseline map: emit `resolved` for any id not in current
4. Compute metric deltas via `metricMeta.ts` lookup; omit unchanged metrics
5. Return `AuditDiff`

`detailChanged` helper: deep-compares `detail`, `remediation`, and `affectedItems` (JSON stringify equality).

---

## 4. Diff Renderers

```typescript
export interface DiffRenderer {
  readonly format: string;
  readonly fileExtension: string;
  render(diff: AuditDiff): string;
}
```

**`DiffHtmlRenderer`** — self-contained HTML, styled consistently with `HtmlRenderer`:
- Header: org name, baseline date vs current date, score delta, grade delta
- Summary bar: counts of new / resolved / severity-changed / detail-changed
- Metric deltas table: colour-coded green/red by `direction`
- Finding change sections (in order): New → Resolved → Severity Changed → Detail Changed
- Unchanged findings omitted by default; togglable via a checkbox

**`DiffJsonRenderer`** — serialises full `AuditDiff` to JSON. Includes `baseline` and `current` in full so the file is self-contained.

**Filename pattern:**
```
sf-audit-diff-{orgId}-{baselineTs}-vs-{currentTs}.{ext}
```

---

## 5. `HistoryRenderer`

**Terminal table** (always shown by `sf audit history`):

```
Audit History: Ministry of Health NZ PopHealth (00D8t0000008aNYEAY)
───────────────────────────────────────────────────────────────────────────────
  #   Date                  Score   Grade   CRIT   HIGH   MED   LOW   Δ Score
───────────────────────────────────────────────────────────────────────────────
  1   2026-03-23 15:10       64      D        2      5     8     3      —
  2   2026-03-24 09:37       71      C        1      4     7     3     +7
  3   2026-04-01 22:56       78      B        0      3     6     4     +7
  4   2026-04-09 11:22       81      B        0      2     5     3     +3
───────────────────────────────────────────────────────────────────────────────
  Trend: ▲ +17 over 4 audits   Best: 81 (2026-04-09)   Worst: 64 (2026-03-23)
```

**HTML timeline** (written to `--output` dir):
- Self-contained HTML with embedded Chart.js (CDN, same approach as `HtmlRenderer`)
- Score trend line chart (x = audit date, y = 0–100)
- Stacked bar chart: finding counts by severity per run
- Metric trend table: one row per metric, values across runs
- Each data point links to the source report file if it exists on disk

**Filename:** `sf-audit-history-{orgId}-{timestamp}.html`

---

## 6. New Commands

### `sf audit diff`

```
sf audit diff <baseline> <current>
              --output ./reports    (default: cwd)
              --format html,json    (default: html,json)
```

- `baseline` and `current` are positional args — paths to JSON report files
- Loads both via `HistoryStore.load()`
- Warns (but continues) if `orgId` differs between files
- Calls `computeDiff()`, renders, writes files
- Prints brief terminal summary: score delta, new/resolved counts
- No `--target-org` required — reads org info from the JSON files

### `sf audit history`

```
sf audit history --target-org <alias>
                 --reports-dir ./reports    (default: ~/.sf/audit-history/{orgId})
                 --output ./reports         (default: cwd, for HTML file)
                 --limit 20                 (default: all)
```

- Resolves `orgId` from `--target-org` auth (no API call — uses cached auth)
- Calls `HistoryStore.list(orgId, reportsDir)`
- Prints terminal table
- Writes HTML timeline file
- If fewer than 2 runs found: prints helpful message and exits cleanly

---

## 7. README Updates

Add a new **"History & Diff"** section to `README.md` covering:
- Auto-archive behaviour (`~/.sf/audit-history/`)
- `sf audit history` usage and flags
- `sf audit diff` usage and flags
- Example output (terminal table snippet)

---

## Impact on Existing Code

| Existing file | Change |
|---------------|--------|
| `src/commands/audit/security.ts` | +3 lines: archive after renderers loop |
| `src/index.ts` | Export new public types |
| Everything else | Untouched |

All 23 checks, `CheckEngine`, `QueryRegistry`, and existing renderers are unchanged.

---

## Test Coverage

- `DiffEngine` — unit tests with fixture `AuditResult` pairs covering all change types and metric directions
- `HistoryStore` — unit tests using a temp directory; archive, list, load, error handling
- `DiffHtmlRenderer` / `DiffJsonRenderer` — snapshot tests against a known `AuditDiff` fixture
- `HistoryRenderer` — snapshot test for terminal table output
- `sf audit diff` / `sf audit history` commands — integration tests using fixture JSON files
