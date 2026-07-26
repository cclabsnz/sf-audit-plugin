import type {
  EventMonitoringCoverage,
  FieldHistoryCoverage,
  BehavioralTablesCoverage,
  CoverageRow,
  CoverageStatus,
} from './types.js';

export function buildCoverage(
  em: EventMonitoringCoverage,
  fh: FieldHistoryCoverage,
  bt: BehavioralTablesCoverage,
): CoverageRow[] {
  const rows: CoverageRow[] = [];

  // Event Monitoring
  const emStatus: CoverageStatus = em.level === 'full' ? 'full' : em.level === 'free-tier' ? 'partial' : 'none';
  rows.push({
    source: 'Event Monitoring',
    status: emStatus,
    detail:
      em.level === 'none'
        ? em.note
        : `${em.level === 'full' ? 'Full (hourly)' : 'Free daily'} · ${em.eventTypeCount} event type(s)`,
  });

  // Field History
  const fhStatus: CoverageStatus = fh.fieldAuditTrail
    ? 'full'
    : fh.trackedObjectCount > 0
      ? 'partial'
      : 'none';
  rows.push({
    source: 'Field History',
    status: fhStatus,
    detail: `${fh.trackedObjectCount} object(s) tracked${fh.fieldAuditTrail ? ' · Field Audit Trail on' : ''}`,
  });

  // Behavioral tables
  const readable = bt.tables.filter((t) => t.access === 'ok');
  const withData = readable.filter((t) => (t.rowCount12mo ?? 0) > 0);
  const btStatus: CoverageStatus = withData.length > 0 ? 'full' : readable.length > 0 ? 'partial' : 'none';
  rows.push({
    source: 'Behavioral Tables',
    status: btStatus,
    detail: `${readable.length}/${bt.tables.length} readable · ${withData.length} with 12mo data`,
  });

  return rows;
}
