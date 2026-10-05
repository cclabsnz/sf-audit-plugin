// src/incident/render/labels.ts
import type { Classification, LogCoverage, WaveOutcome } from '../model.js';

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  'internal-testing': 'Consistent with internal testing',
  'automated-scan': 'Unattributed automated scan',
  organic: 'Organic spike',
  indeterminate: 'Indeterminate',
};

export const RESULT_LABEL: Record<WaveOutcome, string> = {
  'access-gained': 'Access gained',
  'content-returned': 'Content returned, contents unknown',
  'no-evidence': 'No evidence of access',
  'not-assessed': 'Not assessed',
};

export const NOT_COLLECTED = 'not collected';

/** Days whose AuraRequest log was collected. Any other day's counts are unknown, never zero. */
export function auraCollectedDays(logs: LogCoverage[]): Set<string> {
  return new Set(logs.filter((l) => l.type === 'AuraRequest' && l.status === 'collected').map((l) => l.day));
}

/** Every day the bundle covers, collected or not, ascending. */
export function coveredDays(logs: LogCoverage[], extra: string[] = []): string[] {
  return [...new Set([...logs.map((l) => l.day), ...extra])].sort();
}
