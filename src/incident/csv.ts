import { createReadStream, createWriteStream, rmSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { finished } from 'node:stream/promises';
import { id15 } from './model.js';

/**
 * Streams CSV rows from disk. Spike-day event logs exceed V8's ~512 MB string limit, so the
 * whole-file parser in timeline/loadCaptures.ts cannot be used here. The state machine carries
 * across read chunks, including a quote that ends one chunk.
 */
export async function* readCsvCells(path: string, opts?: { chunkSize?: number }): AsyncGenerator<string[]> {
  const chunkSize = opts?.chunkSize ?? (1 << 20);
  const stream = createReadStream(path, { encoding: 'utf8', highWaterMark: chunkSize });
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  let quotePending = false; // saw a quote inside a quoted field; next char decides
  let started = false;
  for await (const chunk of stream as AsyncIterable<string>) {
    for (let i = 0; i < chunk.length; i++) {
      const c = chunk[i];
      if (inQuotes) {
        if (quotePending) {
          quotePending = false;
          if (c === '"') { field += '"'; continue; }
          inQuotes = false; // that quote closed the field; handle c below
        } else if (c === '"') { quotePending = true; continue; }
        else { field += c; continue; }
      }
      if (c === '"' && field === '') { inQuotes = true; started = true; continue; }
      if (c === ',') { row.push(field); field = ''; started = true; continue; }
      if (c === '\r') continue;
      if (c === '\n') {
        row.push(field);
        field = '';
        if (!(row.length === 1 && row[0] === '' && !started)) yield row;
        row = [];
        started = false;
        continue;
      }
      field += c;
      started = true;
    }
  }
  if (started || row.length > 0) { row.push(field); yield row; }
}

export async function* readCsvRecords(path: string, opts?: { chunkSize?: number }): AsyncGenerator<Record<string, string>> {
  let header: string[] | undefined;
  for await (const cells of readCsvCells(path, opts)) {
    if (!header) { header = cells; continue; }
    if (cells.length !== header.length) continue;
    const rec: Record<string, string> = {};
    for (let i = 0; i < header.length; i++) rec[header[i]] = cells[i];
    yield rec;
  }
}

export function csvLine(cells: readonly string[]): string {
  return cells.map((v) => `"${v.replace(/"/g, '""')}"`).join(',') + '\n';
}

export interface FilterResult {
  totalRows: number;
  guestRows: number;
  guestRowsByUser: Record<string, number>;
  malformed: number;
}

/** Copies the rows whose USER_ID or USER_ID_DERIVED belongs to a guest user; counts every row. */
export async function filterLogFile(rawPath: string, outPath: string, guestIds: ReadonlySet<string>): Promise<FilterResult> {
  await mkdir(dirname(outPath), { recursive: true });
  const out = createWriteStream(outPath);
  const result: FilterResult = { totalRows: 0, guestRows: 0, guestRowsByUser: {}, malformed: 0 };
  let header: string[] | undefined;
  let userCols: number[] = [];
  let streamError: Error | null = null;

  out.on('error', (err) => { if (!streamError) streamError = err; });

  const write = async (s: string) => {
    if (streamError) throw streamError;
    if (!out.write(s)) await new Promise<void>((resolve, reject) => {
      const onDrain = () => {
        out.removeListener('error', onError);
        if (streamError) reject(streamError);
        else resolve();
      };
      const onError = (err: Error) => {
        out.removeListener('drain', onDrain);
        streamError = err;
        reject(err);
      };
      out.once('drain', onDrain);
      out.once('error', onError);
    });
  };

  try {
    for await (const cells of readCsvCells(rawPath)) {
      if (!header) {
        header = cells;
        userCols = ['USER_ID', 'USER_ID_DERIVED'].map((h) => header!.indexOf(h)).filter((i) => i >= 0);
        await write(csvLine(cells));
        continue;
      }
      result.totalRows++;
      if (cells.length !== header.length) { result.malformed++; continue; }
      const guest = userCols.map((i) => id15(cells[i])).find((u) => u !== undefined && guestIds.has(u));
      if (!guest) continue;
      result.guestRows++;
      result.guestRowsByUser[guest] = (result.guestRowsByUser[guest] ?? 0) + 1;
      await write(csvLine(cells));
    }
    out.end();
    await finished(out);
  } catch (err) {
    out.destroy();
    rmSync(outPath, { force: true });
    throw err;
  }
  return result;
}
