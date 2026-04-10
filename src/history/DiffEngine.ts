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
