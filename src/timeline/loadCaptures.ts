import * as fs from 'node:fs';
import * as path from 'node:path';
import { readCoverageManifest, type CaptureCoverage } from '@cclabsnz/sf-core';

export interface LoadRequest {
  /** Capture base directory. */
  base: string;
  orgId: string;
  /** Window date, YYYY-MM-DD. */
  date: string;
  /** Hours within that date, two digits. */
  hours: ReadonlyArray<string>;
}

export interface LoadedCaptures {
  rows: Array<Record<string, unknown>>;
  coverage: CaptureCoverage | undefined;
  /** True when any capture file existed for the window at all. */
  windowPresent: boolean;
  /** Lines that could not be parsed. Reported, never fatal. */
  malformed: number;
  /** Files that could not be read. Reported, never fatal. */
  unreadable: number;
}

/**
 * A real CSV reader.
 *
 * Splitting on commas and newlines is wrong for this data specifically, not merely in principle:
 * event log columns carry GraphQL queries, URIs and Aura messages, and a quoted newline in any of
 * them splits one record into two while shifting every later field left. The result still parses,
 * still looks like rows, and is wrong — which is the worst failure mode available to a forensic
 * importer.
 */
export function parseCsv(text: string): Array<Record<string, string>> {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (quoted) {
      if (ch === '"') {
        // A doubled quote inside a quoted field is one literal quote.
        if (text[i + 1] === '"') { cell += '"'; i++; }
        else quoted = false;
      } else cell += ch;
      continue;
    }

    if (ch === '"') { quoted = true; continue; }
    if (ch === ',') { row.push(cell); cell = ''; continue; }
    if (ch === '\r') continue;
    if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; continue; }
    cell += ch;
  }
  if (cell.length > 0 || row.length > 0) { row.push(cell); rows.push(row); }

  const [header, ...body] = rows;
  if (!header) return [];

  return body
    // A trailing newline yields a single empty cell, which is not a record.
    .filter((cells) => !(cells.length === 1 && cells[0] === ''))
    .map((cells) => {
      const record: Record<string, string> = {};
      // Header-driven, so a short row yields empty columns and a long one drops its extras
      // rather than either corrupting the named columns.
      header.forEach((name, idx) => { record[name] = cells[idx] ?? ''; });
      return record;
    });
}

/**
 * Load every captured row for a window.
 *
 * Fault-tolerant by design, matching the capture side: a parse failure on one file must never
 * lose the rest of the window. An investigation frequently runs against the one hour that also
 * happens to contain a truncated download, and losing the other fifty files to it would be
 * self-defeating. Failures are counted and returned so the caller can report them rather than
 * discover them by their absence.
 */
export function loadCaptures(request: LoadRequest): LoadedCaptures {
  const orgDir = path.join(request.base, request.orgId);
  const out: LoadedCaptures = { rows: [], coverage: undefined, windowPresent: false, malformed: 0, unreadable: 0 };

  if (!fs.existsSync(orgDir)) return out;

  for (const entry of safeReadDir(orgDir, out)) {
    if (entry === '_manifests') continue;
    if (entry === '_realtime') { loadRealtime(path.join(orgDir, entry), request, out); continue; }
    loadElf(path.join(orgDir, entry), request, out);
  }

  out.coverage = newestCoverage(path.join(orgDir, '_manifests'));
  return out;
}

function safeReadDir(dir: string, out: LoadedCaptures): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    out.unreadable++;
    return [];
  }
}

/** `{EventType}/{date}/{HH}-{id}.csv` */
function loadElf(typeDir: string, request: LoadRequest, out: LoadedCaptures): void {
  const dayDir = path.join(typeDir, request.date);
  if (!fs.existsSync(dayDir)) return;

  for (const file of safeReadDir(dayDir, out)) {
    const hour = file.slice(0, 2);
    if (!request.hours.includes(hour) || !file.endsWith('.csv')) continue;

    const full = path.join(dayDir, file);
    out.windowPresent = true;
    let text: string;
    try {
      text = fs.readFileSync(full, 'utf-8');
    } catch {
      out.unreadable++;
      continue;
    }
    for (const row of parseCsv(text)) {
      out.rows.push({ ...row, __sourceFile: full, __source: 'EventLogFile' });
    }
  }
}

/** `_realtime/{ObjectName}/{date}/{HH}.ndjson` */
function loadRealtime(realtimeDir: string, request: LoadRequest, out: LoadedCaptures): void {
  for (const object of safeReadDir(realtimeDir, out)) {
    const dayDir = path.join(realtimeDir, object, request.date);
    if (!fs.existsSync(dayDir)) continue;

    for (const file of safeReadDir(dayDir, out)) {
      const hour = file.slice(0, 2);
      if (!request.hours.includes(hour) || !file.endsWith('.ndjson')) continue;

      const full = path.join(dayDir, file);
      out.windowPresent = true;
      let text: string;
      try {
        text = fs.readFileSync(full, 'utf-8');
      } catch {
        out.unreadable++;
        continue;
      }
      for (const line of text.split('\n')) {
        if (line.trim() === '') continue;
        try {
          const parsed: unknown = JSON.parse(line);
          if (parsed && typeof parsed === 'object') {
            out.rows.push({
              ...(parsed as Record<string, unknown>),
              EVENT_TYPE: (parsed as Record<string, unknown>).EVENT_TYPE ?? object,
              __sourceFile: full,
              __source: 'RealTimeEventMonitoring',
            });
          } else out.malformed++;
        } catch {
          // One bad line loses one row, not the file.
          out.malformed++;
        }
      }
    }
  }
}

/**
 * The newest manifest wins.
 *
 * A window can be pulled more than once — a later run adding real-time objects to an earlier
 * ELF-only capture, say — and the most recent record is the one that describes what is actually
 * on disk now.
 */
function newestCoverage(manifestDir: string): CaptureCoverage | undefined {
  if (!fs.existsSync(manifestDir)) return undefined;

  let files: string[];
  try {
    files = fs.readdirSync(manifestDir).filter((f) => f.startsWith('coverage-') && f.endsWith('.json'));
  } catch {
    return undefined;
  }

  // Named coverage-{epochMs}-{rand}.json, so lexical order on the timestamp is chronological
  // for any run this decade; compare numerically anyway rather than relying on that.
  const sorted = files.sort((a, b) => stamp(b) - stamp(a));
  for (const file of sorted) {
    const parsed = readCoverageManifest(path.join(manifestDir, file));
    // A manifest that will not parse is skipped rather than failing the load; the next one
    // down may still describe the window.
    if (parsed) return parsed;
  }
  return undefined;
}

function stamp(fileName: string): number {
  const parsed = Number(fileName.split('-')[1]);
  return Number.isFinite(parsed) ? parsed : 0;
}
