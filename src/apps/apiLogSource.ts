import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RestClient, SoqlClient } from '@cclabsnz/sf-core';
import { apiErrorText } from '../lib/apiErrorText.js';

export const API_LOG_TYPES = ['RestApi', 'BulkApi2', 'GraphQlQueryExecution', 'AuraRequest'] as const;
export type ApiLogType = (typeof API_LOG_TYPES)[number];

export interface ApiLogs {
  csv: Record<ApiLogType, string>;
  /** Log files the query listed. */
  listed: number;
  /** Log files that could not be downloaded or read; their usage is missing from `csv`. */
  failed: { id: string; eventType: string; error: string }[];
}

/** Thrown when the EventLogFile listing itself fails: there is no usage to analyze at all. */
export class ApiLogListingError extends Error {
  public constructor(message: string, public readonly permission: boolean) {
    super(message);
    this.name = 'ApiLogListingError';
  }
}

/**
 * Lists and downloads the API EventLogFiles for the last `since` days. Read-only: one SOQL query and
 * one REST GET per file. A failed listing throws (an empty result would read as "no usage"); a failed
 * download is recorded in `failed` so the caller can flag the analysis as incomplete.
 */
export async function downloadApiLogs(deps: { soql: SoqlClient; rest: RestClient }, since: number): Promise<ApiLogs> {
  const csv: Record<ApiLogType, string> = { RestApi: '', BulkApi2: '', GraphQlQueryExecution: '', AuraRequest: '' };
  let rows: Array<{ Id: string; EventType: string }>;
  try {
    rows = await deps.soql.queryAll<{ Id: string; EventType: string }>(
      `SELECT Id, EventType FROM EventLogFile WHERE EventType IN (${API_LOG_TYPES.map((t) => `'${t}'`).join(', ')}) ` +
        `AND LogDate = LAST_N_DAYS:${since} ORDER BY LogDate DESC`,
    );
  } catch (e) {
    const msg = apiErrorText(e);
    const permission = /INSUFFICIENT_ACCESS|HTTP 403|INVALID_TYPE|not supported/i.test(msg);
    throw new ApiLogListingError(
      permission
        ? `Cannot list API event logs: EventLogFile is not readable (the running user needs View Event Log Files, and the org needs Event Monitoring). ${msg}`
        : `Cannot list API event logs: ${msg}`,
      permission,
    );
  }

  const failed: ApiLogs['failed'] = [];
  if (rows.length === 0) return { csv, listed: 0, failed };

  // A private (0700) temp dir: raw logs hold org data and must not sit at a predictable shared path.
  const dir = mkdtempSync(join(tmpdir(), 'sfaudit-apps-'));
  try {
    for (const r of rows) {
      const tmp = join(dir, `${r.Id}.csv`);
      try {
        await deps.rest.getRawToFile(`/sobjects/EventLogFile/${r.Id}/LogFile`, tmp);
        const content = readFileSync(tmp, 'utf-8');
        if ((API_LOG_TYPES as readonly string[]).includes(r.EventType)) {
          csv[r.EventType as ApiLogType] += '\n' + content;
        }
      } catch (e) {
        failed.push({ id: r.Id, eventType: r.EventType, error: e instanceof Error ? e.message : String(e) });
      } finally {
        rmSync(tmp, { force: true });
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { csv, listed: rows.length, failed };
}

export interface LogCoverage {
  /** Set when there is no usable data at all: the command must stop rather than report. */
  fatal?: string;
  /** Set when some files failed: the analysis runs but is flagged incomplete. */
  incomplete?: string;
  /** Informational: the window simply had no API logs. */
  empty?: string;
}

/** Decides whether downloaded logs are complete, partial, or unusable. Never treats a failure as "no usage". */
export function assessLogCoverage(logs: ApiLogs, since: number): LogCoverage {
  if (logs.listed === 0) return { empty: `No API EventLogFiles in the last ${since} day(s): there is no usage to compare against grants.` };
  if (logs.failed.length === logs.listed) {
    return {
      fatal:
        `None of the ${logs.listed} API log file(s) could be downloaded (first error: ${logs.failed[0].error}). ` +
        'Refusing to report usage from no data.',
    };
  }
  if (logs.failed.length > 0) return { incomplete: `${logs.failed.length} of ${logs.listed} API log file(s) could not be downloaded` };
  return {};
}
