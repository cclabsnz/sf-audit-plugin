import type { EvidenceTier } from '@cclabsnz/sf-core';
import type {
  EventMonitoringCoverage,
  FieldHistoryCoverage,
  BehavioralTablesCoverage,
} from './types.js';

/**
 * Evidence tier grade:
 *  A — full Event Monitoring + Field Audit Trail (richest behavioural evidence).
 *  B — standard behavioural tables accessible with data (history/process rows queryable).
 *  C — metadata + snapshots only (org describable, but little/no behavioural data readable).
 *  D — nothing (org not even describable) — prospective collection recommended.
 */
export function computeEvidenceTier(
  em: EventMonitoringCoverage,
  fh: FieldHistoryCoverage,
  bt: BehavioralTablesCoverage,
  hasCatalog: boolean,
): EvidenceTier {
  if (em.level === 'full' && fh.fieldAuditTrail) return 'A';

  const behavioralWithData = bt.tables.some((t) => t.access === 'ok' && (t.rowCount12mo ?? 0) > 0);
  const anyBehavioralReadable = bt.tables.some((t) => t.access === 'ok');
  if (behavioralWithData || (fh.trackedObjectCount > 0 && anyBehavioralReadable)) return 'B';

  if (hasCatalog || anyBehavioralReadable) return 'C';
  return 'D';
}
