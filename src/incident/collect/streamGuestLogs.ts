// src/incident/collect/streamGuestLogs.ts
import { mkdirSync, rmSync, renameSync, statfsSync } from 'node:fs';
import { join } from 'node:path';
import type { RestClient, SoqlClient } from '@cclabsnz/sf-core';
import { degrades } from './orgErrors.js';
import { filterLogFile } from '../csv.js';
import { logPath } from '../bundleIo.js';
import { LOG_TYPES, type LogCoverage, type LogType, type Wave } from '../model.js';

const nextDay = (d: string, n: number) => new Date(Date.parse(`${d}T00:00:00Z`) + n * 86_400_000).toISOString().slice(0, 10);

export function collectionDays(waves: Wave[]): string[] {
  return [...new Set(waves.flatMap((w) => w.days.flatMap((d) => [nextDay(d, -1), d, nextDay(d, 1)])))].sort();
}

/**
 * Downloads each daily log with sf-core's getRawToFile (fetch is banned in src/ by the
 * read-only invariant), filters it to guest rows with a streaming parser, then deletes the raw
 * file. Peak disk use is one raw log, up to ~600 MB on a spike day.
 */
export async function streamGuestLogs(
  deps: { soql: SoqlClient; rest: RestClient },
  bundleDir: string,
  days: string[],
  guestIds: ReadonlySet<string>,
  warn: (m: string) => void,
  reuse: (type: LogType, day: string) => LogCoverage | undefined = () => undefined,
): Promise<LogCoverage[]> {
  const coverage: LogCoverage[] = [];
  const blank = (type: LogType, day: string, status: LogCoverage['status'], detail?: string): LogCoverage =>
    ({ type, day, status, totalRows: 0, guestRows: 0, guestRowsByUser: {}, malformed: 0, detail });
  if (days.length === 0) return coverage;

  let files: Array<{ Id: string; EventType: string; LogDate: string; LogFileLength?: number }>;
  try {
    files = await deps.soql.queryAll(
      `SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE Interval = 'Daily' AND EventType IN (${LOG_TYPES.map((t) => `'${t}'`).join(',')}) ` +
      `AND LogDate >= ${days[0]}T00:00:00Z AND LogDate <= ${days[days.length - 1]}T00:00:00Z`);
  } catch (e) {
    if (!degrades(e)) throw e;
    return days.flatMap((d) => LOG_TYPES.map((t) => blank(t, d, 'no-permission', 'EventLogFile is not readable: the running user needs the View Event Log Files permission.')));
  }

  const tmp = join(bundleDir, '.tmp');
  // A killed earlier run can leave raw, unfiltered logs here, which contain non-guest data.
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  for (const day of days) {
    for (const type of LOG_TYPES) {
      const prior = reuse(type, day);
      if (prior) { coverage.push(prior); continue; }
      const f = files.find((x) => x.EventType === type && x.LogDate.slice(0, 10) === day);
      if (!f) { coverage.push(blank(type, day, 'missing', 'No EventLogFile for this day (past retention, not generated yet, or no activity).')); continue; }
      const raw = join(tmp, `${f.Id}.csv`);
      const rel = logPath(type, day);
      const part = join(bundleDir, `${rel}.part`);
      let freeBytes: number | undefined;
      try { const s = statfsSync(bundleDir); freeBytes = Number(s.bavail) * Number(s.bsize); } catch { freeBytes = undefined; }
      if (freeBytes !== undefined && f.LogFileLength && freeBytes < 1.2 * f.LogFileLength) {
        const mb = (n: number) => Math.ceil(n / 1_048_576);
        rmSync(tmp, { recursive: true, force: true });
        throw new Error(`Not enough free disk space for ${type} ${day} (${mb(1.2 * f.LogFileLength)} MB needed, ${Math.floor(freeBytes / 1_048_576)} MB free). Free space and re-run; completed logs are kept.`);
      }
      try {
        await deps.rest.getRawToFile(`/sobjects/EventLogFile/${f.Id}/LogFile`, raw);
        const r = await filterLogFile(raw, part, guestIds);
        renameSync(part, join(bundleDir, rel));
        coverage.push({ type, day, status: 'collected', ...r, file: rel });
      } catch (e) {
        if ((e as { code?: string })?.code === 'ENOSPC' || /HTTP 401/.test(String(e))) {
          rmSync(part, { force: true });
          rmSync(raw, { force: true });
          rmSync(tmp, { recursive: true, force: true });
          throw e;
        }
        warn(`Could not collect ${type} for ${day}: ${String(e)}`);
        coverage.push(blank(type, day, /INSUFFICIENT_ACCESS|HTTP 403/i.test(String(e)) ? 'no-permission' : 'failed', String(e)));
        rmSync(part, { force: true });
      } finally {
        rmSync(raw, { force: true });
      }
    }
  }
  rmSync(tmp, { recursive: true, force: true });
  return coverage;
}
