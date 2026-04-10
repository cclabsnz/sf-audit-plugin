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
