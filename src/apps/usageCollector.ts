import type { AppUsage, Verb } from './types.js';

function parseCsv(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  const header = splitCsvLine(lines[0]);
  const headerToken = header[0]; // e.g. "EVENT_TYPE"
  const rows: Record<string, string>[] = [];
  for (const line of lines.slice(1)) {
    // Skip embedded header rows (from multi-file concatenation) and blank lines.
    const firstCell = splitCsvLine(line)[0];
    if (firstCell === headerToken) continue;
    const cells = splitCsvLine(line);
    const row: Record<string, string> = {};
    header.forEach((h, i) => (row[h] = cells[i] ?? ''));
    rows.push(row);
  }
  return rows;
}

// Minimal RFC-4180 line splitter (handles quoted cells; EventLogFile has no embedded newlines
// in these columns). Sufficient for API/RestApi logs.
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inq = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inq) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') inq = false;
      else cur += c;
    } else if (c === '"') inq = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

function verbOf(method: string): Verb {
  const m = method.toUpperCase();
  if (m === 'DELETE') return 'delete';
  if (m === 'POST' || m === 'PATCH' || m === 'PUT') return 'write';
  return 'read';
}

interface Acc {
  objects: Map<string, Set<Verb>>;
  requests: number;
  rows: number;
  users: Set<string>;
}

export interface UsageResult {
  usage: AppUsage[];
  totalRows: number;
  attributedRows: number;
  attributionRatePct: number;
}

export interface CollectUsageOptions {
  soapApiCsv?: string;
  bulkApi2Csv?: string;
  graphQlCsv?: string;
  auraCsv?: string;
}

export function collectUsage(
  restApiCsv: string,
  optsOrSoap?: CollectUsageOptions | string,
): UsageResult {
  const opts: CollectUsageOptions =
    typeof optsOrSoap === 'string'
      ? { soapApiCsv: optsOrSoap }
      : optsOrSoap ?? {};

  const byApp = new Map<string, Acc>();
  let totalRows = 0;
  let attributed = 0;

  const processFile = (
    csvText: string | undefined,
    entityGetter: (r: Record<string, string>) => string | undefined,
    verbGetter: (r: Record<string, string>) => Verb,
    rowsGetter: (r: Record<string, string>) => number,
  ) => {
    if (!csvText) return;
    const rows = parseCsv(csvText);
    totalRows += rows.length;
    for (const row of rows) {
      const appId = row.CONNECTED_APP_ID ?? '';
      if (!appId) continue;
      attributed++;
      let a = byApp.get(appId);
      if (!a) {
        a = { objects: new Map(), requests: 0, rows: 0, users: new Set() };
        byApp.set(appId, a);
      }
      a.requests++;
      a.rows += rowsGetter(row);
      if (row.USER_ID) a.users.add(row.USER_ID);
      const entity = entityGetter(row);
      if (entity) {
        // Support comma-separated entities if present
        const entityNames = entity.split(',').map((e) => e.trim()).filter(Boolean);
        for (const ent of entityNames) {
          const verbs = a.objects.get(ent) ?? new Set<Verb>();
          verbs.add(verbGetter(row));
          a.objects.set(ent, verbs);
        }
      }
    }
  };

  // 1. RestApi logs
  processFile(
    restApiCsv,
    (r) => r.ENTITY_NAME,
    (r) => verbOf(r.METHOD ?? r.METHOD_NAME ?? 'GET'),
    (r) => Number(r.ROWS_PROCESSED) || 0,
  );

  // 2. BulkApi2 logs
  processFile(
    opts.bulkApi2Csv,
    (r) => r.ENTITY_NAME,
    (r) => {
      const op = (r.OPERATION ?? r.OPERATION_TYPE ?? '').toLowerCase();
      if (op === 'delete' || op === 'harddelete' || op === 'hard_delete') return 'delete';
      if (op === 'insert' || op === 'update' || op === 'upsert') return 'write';
      return 'read';
    },
    (r) => Number(r.ROWS_PROCESSED || r.NUMBER_RECORDS_PROCESSED || 0) || 0,
  );

  // 3. GraphQlQueryExecution logs
  processFile(
    opts.graphQlCsv,
    (r) => r.ENTITY_NAME || r.TARGET_ENTITY,
    (r) => {
      const op = (r.OPERATION_TYPE ?? r.OPERATION ?? '').toLowerCase();
      return op.includes('mutation') ? 'write' : 'read';
    },
    (r) => Number(r.ROWS_PROCESSED || r.ROW_COUNT || 0) || 0,
  );

  // 4. AuraRequest logs
  processFile(
    opts.auraCsv,
    (r) => r.ENTITY_NAME,
    (r) => verbOf(r.METHOD_NAME ?? r.METHOD ?? 'GET'),
    (r) => Number(r.ROWS_PROCESSED || 0) || 0,
  );

  const soapUsers = new Set<string>();
  if (opts.soapApiCsv) {
    for (const row of parseCsv(opts.soapApiCsv)) if (row.USER_ID) soapUsers.add(row.USER_ID);
  }

  const usage: AppUsage[] = [...byApp.entries()].map(([appId, a]) => ({
    appId,
    objects: [...a.objects.entries()].map(([object, verbs]) => ({ object, verbs: [...verbs].sort() })),
    requests: a.requests,
    rowsProcessed: a.rows,
    userIds: [...a.users].sort(),
    soapOnly: false,
  }));

  return {
    usage: usage.sort((x, y) => y.requests - x.requests),
    totalRows,
    attributedRows: attributed,
    attributionRatePct: totalRows ? Math.round((100 * attributed) / totalRows) : 0,
  };
}
