// src/events/pullEventLogs.ts
// Orchestrates a single `audit events pull` run: discover the org's free Daily EventLogFile
// rows, download the CSV body of any not already on disk, and record a per-run manifest.
// All org I/O is behind the injected SoqlClient/RestClient, so this is unit-testable with
// mocked clients — it never touches a real org.
import type { SoqlClient } from '../api/SoqlClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { EventLogAccess } from '../context/AuditCache.js';
import { classifyEventLogAccessError } from '../checks/eventLogAccess.js';
import { EventBaselineStore } from './EventBaselineStore.js';
import { buildEventLogQuery, toLogDate } from './eventLogQuery.js';

/** The subset of EventLogFile fields the discovery query returns. */
export interface EventLogFileRow {
  Id: string;
  EventType: string;
  LogDate: string;
  LogFileLength?: number;
  Interval?: string;
  LogFileFieldNames?: string;
}

/** Outcome for one EventLogFile row in a run. */
export interface PulledLog {
  id: string;
  eventType: string;
  logDate: string;
  bytes: number;
  savedPath: string;
  status: 'downloaded' | 'skipped' | 'failed';
}

/** Structured result of a pull run — returned by the command. */
export interface EventsPullResult {
  orgId: string;
  since: number;
  storagePath: string;
  found: number;
  downloaded: number;
  skipped: number;
  failed: number;
  totalBytes: number;
  logs: PulledLog[];
  manifestPath?: string;
  /** Set when the EventLogFile query itself failed (no crash); tells license vs permission apart. */
  accessError?: EventLogAccess;
}

export interface PullDeps {
  soql: SoqlClient;
  rest: RestClient;
  store: EventBaselineStore;
  orgId: string;
}

export interface PullOptions {
  since: number;
  types?: string[];
  /** Optional sink for non-fatal warnings (per-file download failures). */
  warn?: (msg: string) => void;
}

export async function pullEventLogs(deps: PullDeps, opts: PullOptions): Promise<EventsPullResult> {
  const { soql, rest, store, orgId } = deps;
  const since = opts.since;
  const storagePath = store.orgDir(orgId);

  const base: EventsPullResult = {
    orgId,
    since,
    storagePath,
    found: 0,
    downloaded: 0,
    skipped: 0,
    failed: 0,
    totalBytes: 0,
    logs: [],
  };

  let rows: EventLogFileRow[];
  try {
    rows = await soql.queryAll<EventLogFileRow>(buildEventLogQuery({ since, types: opts.types }));
  } catch (err) {
    // Inaccessible EventLogFile (unlicensed / no permission) must not crash the command.
    return { ...base, accessError: classifyEventLogAccessError(err) };
  }

  base.found = rows.length;

  for (const row of rows) {
    const logDate = toLogDate(row.LogDate);

    if (store.has(orgId, row.EventType, logDate, row.Id)) {
      base.skipped += 1;
      base.logs.push({
        id: row.Id,
        eventType: row.EventType,
        logDate,
        bytes: 0,
        savedPath: store.pathFor(orgId, row.EventType, logDate, row.Id),
        status: 'skipped',
      });
      continue;
    }

    try {
      const body = await rest.getRaw(`/sobjects/EventLogFile/${row.Id}/LogFile`);
      const savedPath = store.save(orgId, row.EventType, logDate, row.Id, body);
      const bytes = Buffer.byteLength(body, 'utf-8');
      base.downloaded += 1;
      base.totalBytes += bytes;
      base.logs.push({ id: row.Id, eventType: row.EventType, logDate, bytes, savedPath, status: 'downloaded' });
    } catch (err) {
      base.failed += 1;
      base.logs.push({
        id: row.Id,
        eventType: row.EventType,
        logDate,
        bytes: 0,
        savedPath: store.pathFor(orgId, row.EventType, logDate, row.Id),
        status: 'failed',
      });
      opts.warn?.(`Failed to download EventLogFile ${row.Id} (${row.EventType} ${logDate}): ${String(err)}`);
    }
  }

  // Only write a manifest when something was actually captured — a pure all-skipped or
  // empty run leaves no new record to make.
  if (base.downloaded > 0) {
    base.manifestPath = store.writeManifest(orgId, {
      orgId,
      since,
      pulledAt: new Date().toISOString(),
      found: base.found,
      downloaded: base.downloaded,
      skipped: base.skipped,
      failed: base.failed,
      totalBytes: base.totalBytes,
      logs: base.logs,
    });
  }

  return base;
}
