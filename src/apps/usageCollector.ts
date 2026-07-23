import type { AppUsage, Verb } from './types.js';

function parseCsv(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  const header = splitCsvLine(lines[0]);
  return lines.slice(1).map((line) => {
    const cells = splitCsvLine(line);
    const row: Record<string, string> = {};
    header.forEach((h, i) => (row[h] = cells[i] ?? ''));
    return row;
  });
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

export function collectUsage(restApiCsv: string, soapApiCsv?: string): UsageResult {
  const rows = parseCsv(restApiCsv);
  const byApp = new Map<string, Acc>();
  let attributed = 0;

  for (const row of rows) {
    const appId = row.CONNECTED_APP_ID ?? '';
    if (!appId) continue;
    attributed++;
    let a = byApp.get(appId);
    if (!a) { a = { objects: new Map(), requests: 0, rows: 0, users: new Set() }; byApp.set(appId, a); }
    a.requests++;
    a.rows += Number(row.ROWS_PROCESSED) || 0;
    if (row.USER_ID) a.users.add(row.USER_ID);
    const entity = row.ENTITY_NAME;
    if (entity) {
      const verbs = a.objects.get(entity) ?? new Set<Verb>();
      verbs.add(verbOf(row.METHOD ?? row.METHOD_NAME ?? 'GET'));
      a.objects.set(entity, verbs);
    }
  }

  const soapUsers = new Set<string>();
  if (soapApiCsv) {
    for (const row of parseCsv(soapApiCsv)) if (row.USER_ID) soapUsers.add(row.USER_ID);
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
    totalRows: rows.length,
    attributedRows: attributed,
    attributionRatePct: rows.length ? Math.round((100 * attributed) / rows.length) : 0,
  };
}
