// Plugin entry point — oclif discovers commands from lib/commands/ automatically
export type { AuditResult } from './findings/AuditResult.js';
export type { Finding } from './findings/Finding.js';
export type { RiskLevel } from './findings/RiskLevel.js';
export type { OrgMetrics } from './context/OrgMetrics.js';
export type { AuditDiff, FindingChange, FindingChangeType, MetricDelta } from './history/AuditDiff.js';
export { HistoryStore } from './history/HistoryStore.js';
export { computeDiff } from './history/DiffEngine.js';
