// Plugin entry point — oclif discovers commands from lib/commands/ automatically
export type { AuditResult } from './findings/AuditResult.js';
export type { Finding } from './findings/Finding.js';
export type { RiskLevel } from '@cclabsnz/sf-core';
export type { OrgMetrics } from '@cclabsnz/sf-core';
export type { AuditDiff, FindingChange, FindingChangeType, MetricDelta } from './history/AuditDiff.js';
export { HistoryStore } from './history/HistoryStore.js';
export { computeDiff } from './history/DiffEngine.js';
