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
  /** Window start, inclusive. Omit to keep every row in the selected files. */
  startMs?: number;
  /** Window end, exclusive. */
  endMs?: number;
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
  /** Rows kept despite an unreadable timestamp — they could not be placed in or out of the window. */
  undated: number;
}

/** Salesforce org ids are 15 or 18 characters and start 00D. */
const ORG_ID = /^00D[A-Za-z0-9]{12}([A-Za-z0-9]{3})?$/;

/**
 * Which orgs have captures under this base directory.
 *
 * The store is keyed by org id, so the directory names already hold the answer. Reading them
 * keeps the command offline: resolving an alias would mean asking Salesforce, and this command
 * exists to work when the org is unreachable or its credentials are gone.
 *
 * Filtered by shape because the base directory belongs to the operator and may hold anything —
 * notes, exports, an unrelated folder.
 */
export function discoverCapturedOrgs(base: string): string[] {
  try {
    return fs
      .readdirSync(base, { withFileTypes: true })
      .filter((e) => e.isDirectory() && ORG_ID.test(e.name))
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}

/**
 * Settle on the org to read, or explain why that is not possible.
 *
 * Inferring the only captured org removes a step that exists for no reason; an operator with one
 * capture directory should not have to retype an eighteen-character identifier they cannot check
 * by eye. Where the answer is genuinely ambiguous the command asks rather than picks: choosing
 * one of several would analyse the wrong org and produce output that looks entirely correct.
 */
export function resolveOrgId(base: string, explicit: string | undefined): string {
  const captured = discoverCapturedOrgs(base);

  if (explicit) {
    if (captured.length > 0 && !captured.includes(explicit)) {
      throw new Error(
        `No captures for ${explicit} under ${base}.\n` +
          `Captured here: ${captured.join(', ')}\n` +
          'If that id is right, capture the org first: sf audit events pull --target-org <alias>',
      );
    }
    return explicit;
  }

  if (captured.length === 1) return captured[0];

  if (captured.length === 0) {
    throw new Error(
      `No captures found under ${base}.\n` +
        'Capture an org first:  sf audit events pull --target-org <alias>',
    );
  }

  throw new Error(
    `Several orgs are captured under ${base}; name the one to read with --org-id.\n` +
      captured.map((id) => `  ${id}`).join('\n'),
  );
}

/** One captured day, and how much of it there is. */
export interface CapturedDay {
  date: string;
  /** How many event types have a capture for that date. */
  types: number;
  /** Hours captured in the hourly layout. Empty for a daily capture, which covers the day. */
  hours: string[];
}

/**
 * Which days have captures, read off the store's own layout.
 *
 * "No captures for that window" is only half an answer. The operator's next question is which
 * windows do exist, and without it they go and re-pull data that may already be on disk under a
 * date they guessed wrong. The store is keyed by date, so it already knows.
 *
 * An empty file does not count, matching what counts as captured everywhere else — a partial
 * write is not a capture, and offering it as an available window would send somebody to
 * investigate an hour that holds nothing.
 */
export function describeCaptures(base: string, orgId: string): CapturedDay[] {
  const orgDir = path.join(base, orgId);
  const days = new Map<string, { types: Set<string>; hours: Set<string> }>();

  const note = (date: string, type: string, hour?: string): void => {
    let day = days.get(date);
    if (!day) days.set(date, (day = { types: new Set(), hours: new Set() }));
    day.types.add(type);
    if (hour) day.hours.add(hour);
  };

  let entries: string[];
  try {
    entries = fs.readdirSync(orgDir);
  } catch {
    return [];
  }

  for (const entry of entries) {
    if (entry === '_manifests') continue;
    const entryPath = path.join(orgDir, entry);

    if (entry === '_realtime') {
      for (const object of safeList(entryPath)) {
        for (const date of safeList(path.join(entryPath, object))) {
          for (const file of safeList(path.join(entryPath, object, date))) {
            if (file.endsWith('.ndjson') && nonEmpty(path.join(entryPath, object, date, file))) {
              note(date, object, file.slice(0, 2));
            }
          }
        }
      }
      continue;
    }

    for (const child of safeList(entryPath)) {
      const full = path.join(entryPath, child);
      // Daily: {date}-{id}.csv
      const daily = /^(\d{4}-\d{2}-\d{2})-.*\.csv$/.exec(child);
      if (daily && nonEmpty(full)) { note(daily[1], entry); continue; }
      // Hourly: a directory named for the date.
      if (/^\d{4}-\d{2}-\d{2}$/.test(child)) {
        for (const file of safeList(full)) {
          if (file.endsWith('.csv') && nonEmpty(path.join(full, file))) note(child, entry, file.slice(0, 2));
        }
      }
    }
  }

  return [...days]
    .map(([date, d]) => ({ date, types: d.types.size, hours: [...d.hours].sort() }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

function safeList(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
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
  const out: LoadedCaptures = { rows: [], coverage: undefined, windowPresent: false, malformed: 0, unreadable: 0, undated: 0 };

  if (!fs.existsSync(orgDir)) return out;

  for (const entry of safeReadDir(orgDir, out)) {
    if (entry === '_manifests') continue;
    if (entry === '_realtime') { loadRealtime(path.join(orgDir, entry), request, out); continue; }
    loadElf(path.join(orgDir, entry), request, out);
  }

  out.coverage = newestCoverage(path.join(orgDir, '_manifests'));
  return out;
}

/**
 * When did this row happen?
 *
 * EventLogFile carries both an ISO timestamp and Salesforce's own compact form; real-time
 * objects carry EventDate. Any one of them will do, and the compact form has to be assembled
 * because it does not parse as a date on its own.
 */
function rowTimeMs(row: Record<string, unknown>): number | undefined {
  for (const key of ['TIMESTAMP_DERIVED', 'EventDate', 'CreatedDate']) {
    const value = row[key];
    if (typeof value === 'string' && value.trim() !== '') {
      const parsed = Date.parse(value);
      if (!Number.isNaN(parsed)) return parsed;
    }
  }
  // 20260802043000.000 — year month day hour minute second, no separators.
  const compact = row.TIMESTAMP;
  if (typeof compact === 'string') {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?$/.exec(compact.trim());
    if (m) {
      return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], m[7] ? +m[7].slice(0, 3) : 0);
    }
  }
  return undefined;
}

/**
 * Keep a row if it falls in the window — or if its time cannot be read at all.
 *
 * A daily capture file spans twenty-four hours, so selecting the file is not selecting the
 * window; without this, asking for one hour returns the day. The window is half-open so two
 * consecutive windows partition their rows instead of both claiming the boundary.
 *
 * A row whose timestamp will not parse is kept rather than dropped. It cannot be placed in or
 * out of the window, and dropping it would lose evidence with no trace; kept, it appears in the
 * output with an empty timestamp where a reviewer can see it and judge.
 */
function inWindow(row: Record<string, unknown>, request: LoadRequest, out: LoadedCaptures): boolean {
  if (request.startMs === undefined || request.endMs === undefined) return true;
  const at = rowTimeMs(row);
  if (at === undefined) { out.undated++; return true; }
  return at >= request.startMs && at < request.endMs;
}

/**
 * A file that exists but holds nothing is not a capture.
 *
 * sf-core 0.3.0 made presence on disk mean complete: the capture writes atomically and treats a
 * zero-byte file as absent, because a run killed between create and write leaves one behind and
 * counting it as captured retires that hour permanently. The reader has to agree, or a gap the
 * capture side now refuses to hide reappears here as a window reported captured with no data in
 * it — which is precisely the ambiguity this command exists to remove.
 */
function nonEmpty(filePath: string): boolean {
  try {
    return fs.statSync(filePath).size > 0;
  } catch {
    return false;
  }
}

function safeReadDir(dir: string, out: LoadedCaptures): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    out.unreadable++;
    return [];
  }
}

/**
 * Both EventLogFile layouts.
 *
 *   `{EventType}/{date}-{id}.csv`        daily — what the free tier serves, and what
 *                                        `sf audit events pull` writes by default
 *   `{EventType}/{date}/{HH}-{id}.csv`   hourly
 *
 * Reading only the hourly form would make this command blind to the captures it exists to read.
 * A day can hold both at once, so both are read and the rows are filtered to the window
 * afterwards.
 */
function loadElf(typeDir: string, request: LoadRequest, out: LoadedCaptures): void {
  const readFile = (full: string): void => {
    if (!nonEmpty(full)) return;
    out.windowPresent = true;
    let text: string;
    try {
      text = fs.readFileSync(full, 'utf-8');
    } catch {
      out.unreadable++;
      return;
    }
    for (const row of parseCsv(text)) {
      const record = { ...row, __sourceFile: full, __source: 'EventLogFile' };
      if (inWindow(record, request, out)) out.rows.push(record);
    }
  };

  // Daily: a file named for the date, directly under the event type.
  for (const entry of safeReadDir(typeDir, out)) {
    if (entry.startsWith(`${request.date}-`) && entry.endsWith('.csv')) {
      readFile(path.join(typeDir, entry));
    }
  }

  // Hourly: a directory named for the date, holding a file per hour.
  const dayDir = path.join(typeDir, request.date);
  if (!fs.existsSync(dayDir) || !fs.statSync(dayDir).isDirectory()) return;

  for (const file of safeReadDir(dayDir, out)) {
    const hour = file.slice(0, 2);
    if (!request.hours.includes(hour) || !file.endsWith('.csv')) continue;
    readFile(path.join(dayDir, file));
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
      if (!nonEmpty(full)) continue;
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
            const record = {
              ...(parsed as Record<string, unknown>),
              EVENT_TYPE: (parsed as Record<string, unknown>).EVENT_TYPE ?? object,
              __sourceFile: full,
              __source: 'RealTimeEventMonitoring',
            };
            if (inWindow(record, request, out)) out.rows.push(record);
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
