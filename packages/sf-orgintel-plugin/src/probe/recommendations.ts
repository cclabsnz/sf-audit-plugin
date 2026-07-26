import type {
  OrgBasics,
  EventMonitoringCoverage,
  FieldHistoryCoverage,
  BehavioralTablesCoverage,
  Recommendation,
} from './types.js';
import type { SObjectCatalog } from './sobjectCatalog.js';

/**
 * Deterministic "flip these switches to see more" recommendations, derived purely from the
 * evidence gaps found. Ordered high -> low priority.
 */
export function buildRecommendations(
  _org: OrgBasics,
  em: EventMonitoringCoverage,
  fh: FieldHistoryCoverage,
  bt: BehavioralTablesCoverage,
  _catalog: SObjectCatalog,
): Recommendation[] {
  const recs: Recommendation[] = [];

  // Event Monitoring access gaps
  if (em.access === 'no-permission') {
    recs.push({
      title: 'Grant "View Event Log Files" to the running user',
      detail:
        'EventLogFile is not readable, so login/API/error behaviour is invisible. Grant the permission and re-run to unlock free daily event evidence.',
      priority: 'high',
    });
  } else if (em.level === 'free-tier') {
    recs.push({
      title: 'Consider hourly Event Monitoring for near-real-time evidence',
      detail:
        'Only Daily-interval EventLogFile logs are present. The Event Monitoring add-on adds hourly events and more event types for finer process timing.',
      priority: 'low',
    });
  }

  // Field history gaps
  const untrackedKeyObjects = fh.objects
    .filter((o) => !o.custom && !o.historyTrackingEnabled)
    .map((o) => o.object);
  if (fh.trackedObjectCount === 0) {
    recs.push({
      title: 'Enable field history tracking on your core objects',
      detail:
        'No object has history tracking on. Turn it on for the status/stage fields of your busiest objects to make process transitions observable' +
        (untrackedKeyObjects.length > 0 ? ` (e.g. ${untrackedKeyObjects.slice(0, 5).join(', ')}).` : '.'),
      priority: 'high',
    });
  } else if (untrackedKeyObjects.length > 0) {
    recs.push({
      title: 'Extend field history tracking to more key objects',
      detail: `History tracking is on for ${fh.trackedObjectCount} object(s), but these key objects are untracked: ${untrackedKeyObjects
        .slice(0, 6)
        .join(', ')}. Track their status/stage fields to see their lifecycles.`,
      priority: 'medium',
    });
  }

  if (!fh.fieldAuditTrail && fh.trackedObjectCount > 0) {
    recs.push({
      title: 'Field Audit Trail would retain history beyond the standard window',
      detail:
        'Standard field history is retained ~18-24 months. Shield Field Audit Trail extends retention (up to 10 years) for long-horizon process analysis.',
      priority: 'low',
    });
  }

  // Behavioral table access gaps
  const unreadable = bt.tables.filter((t) => t.access === 'no-access').map((t) => t.name);
  if (unreadable.length > 0) {
    recs.push({
      title: 'Grant read access to behavioural tables',
      detail: `These tables exist but are not readable by the running user: ${unreadable.join(
        ', ',
      )}. Granting read access enriches the process evidence available.`,
      priority: 'medium',
    });
  }

  return recs;
}
