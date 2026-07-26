import type { SoqlClient } from '@cclabsnz/sf-core';
import { classifyEventLogAccessError } from '@cclabsnz/sf-core';
import type { EventMonitoringCoverage, EmLevel, EventLogAccessStatus } from './types.js';
import { unique } from './util.js';

interface ElfRow {
  EventType: string;
  Interval: string;
}

/**
 * Classify the org's Event Monitoring level from EventLogFile access and the intervals
 * it exposes. Hourly-interval events are the paid Event Monitoring add-on; Daily-only is
 * the free tier available on EE/UE/PE/DE; no access at all is "none".
 */
export async function probeEventMonitoring(soql: SoqlClient): Promise<EventMonitoringCoverage> {
  try {
    // Bounded, read-only sample of what event types/intervals exist in the last 30 days.
    const rows = await soql.queryAll<ElfRow>(
      'SELECT EventType, Interval FROM EventLogFile WHERE LogDate = LAST_N_DAYS:30 LIMIT 1000',
    );
    const eventTypes = unique(rows.map((r) => r.EventType).filter(Boolean)).sort();
    const intervals = unique(rows.map((r) => r.Interval).filter(Boolean)).sort();
    const hasHourly = intervals.some((i) => i.toLowerCase() === 'hourly');

    let level: EmLevel;
    let note: string;
    if (eventTypes.length === 0) {
      level = 'none';
      note = 'EventLogFile is readable but no log rows were produced in the last 30 days.';
    } else if (hasHourly) {
      level = 'full';
      note = `Full Event Monitoring: hourly-interval events present (${eventTypes.length} event type(s)).`;
    } else {
      level = 'free-tier';
      note = `Free daily EventLogFile logs: ${eventTypes.length} event type(s), Daily interval only. Hourly events need the Event Monitoring add-on.`;
    }
    return { level, access: 'ok', intervals, eventTypes, eventTypeCount: eventTypes.length, note };
  } catch (err) {
    const access = classifyEventLogAccessError(err) as EventLogAccessStatus;
    return {
      level: 'none',
      access,
      intervals: [],
      eventTypes: [],
      eventTypeCount: 0,
      note: accessNote(access),
    };
  }
}

function accessNote(access: EventLogAccessStatus): string {
  switch (access) {
    case 'no-permission':
      return 'EventLogFile is not readable: the running user lacks the "View Event Log Files" permission.';
    case 'not-enabled':
      return 'EventLogFile is not available on this org/edition (needs EE/UE/PE, or Developer Edition).';
    default:
      return 'EventLogFile could not be queried; Event Monitoring coverage is unknown.';
  }
}
