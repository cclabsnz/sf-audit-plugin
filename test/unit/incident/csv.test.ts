import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { readCsvCells, readCsvRecords, csvLine, filterLogFile } from '../../../src/incident/csv.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-csv-'));
const w = (name: string, body: string) => { const p = path.join(dir, name); fs.writeFileSync(p, body); return p; };
async function all<T>(g: AsyncIterable<T>): Promise<T[]> { const out: T[] = []; for await (const x of g) out.push(x); return out; }

describe('readCsvCells', () => {
  it('handles quoted commas, doubled quotes, CRLF and newlines inside fields', async () => {
    const p = w('q.csv', '"A","B"\r\n"x,1","he said ""hi"""\r\n"line1\nline2",""\r\n');
    expect(await all(readCsvCells(p))).toEqual([['A', 'B'], ['x,1', 'he said "hi"'], ['line1\nline2', '']]);
  });
  it('handles a quote split across read chunks', async () => {
    const big = '"A"\n' + '"' + 'y'.repeat((1 << 20) - 2) + '""z"\n';
    const p = w('split.csv', big);
    const rows = await all(readCsvCells(p));
    expect(rows[1][0].endsWith('y"z')).toBe(true);
  });
  it('yields nothing for an empty file and only the header for a header-only file', async () => {
    expect(await all(readCsvCells(w('e.csv', '')))).toEqual([]);
    expect(await all(readCsvCells(w('h.csv', '"A","B"\n')))).toEqual([['A', 'B']]);
  });
});

describe('readCsvRecords + csvLine', () => {
  it('round-trips records through csvLine', async () => {
    const p = w('r.csv', csvLine(['USER_ID', 'X']) + csvLine(['005xx000000gstA', 'a,"b"\nc']));
    expect(await all(readCsvRecords(p))).toEqual([{ USER_ID: '005xx000000gstA', X: 'a,"b"\nc' }]);
  });
});

describe('filterLogFile', () => {
  it('keeps rows whose USER_ID or USER_ID_DERIVED prefix is a guest, counts the rest', async () => {
    const raw = w('raw.csv',
      csvLine(['USER_ID', 'USER_ID_DERIVED', 'CLIENT_IP']) +
      csvLine(['005xx000000gstA', '005xx000000gstAAAA', '10.0.0.1']) +
      csvLine(['', '005xx000000gstBAAA', '10.0.0.2']) +
      csvLine(['005xx000000othr', '', '10.0.0.3']) +
      csvLine(['bad']));
    const out = path.join(dir, 'out.csv');
    const r = await filterLogFile(raw, out, new Set(['005xx000000gstA', '005xx000000gstB']));
    expect(r).toEqual({ totalRows: 4, guestRows: 2, guestRowsByUser: { '005xx000000gstA': 1, '005xx000000gstB': 1 }, malformed: 1 });
    const kept = await all(readCsvRecords(out));
    expect(kept.map((k) => k.CLIENT_IP)).toEqual(['10.0.0.1', '10.0.0.2']);
  });
  it('returns zeros for header-only and empty files', async () => {
    const out = path.join(dir, 'o2.csv');
    expect(await filterLogFile(w('ho.csv', csvLine(['USER_ID'])), out, new Set(['x']))).toEqual({ totalRows: 0, guestRows: 0, guestRowsByUser: {}, malformed: 0 });
    expect(await filterLogFile(w('em.csv', ''), out, new Set(['x']))).toEqual({ totalRows: 0, guestRows: 0, guestRowsByUser: {}, malformed: 0 });
  });
  it('filters a large file with bounded heap growth', async () => {
    const p = path.join(dir, 'big.csv');
    const fd = fs.openSync(p, 'w');
    fs.writeSync(fd, csvLine(['USER_ID', 'ACTION_MESSAGE']));
    const chunk: string[] = [];
    for (let i = 0; i < 300_000; i++) {
      chunk.push(csvLine([i % 10 === 0 ? '005xx000000gstA' : '005xx000000othr', 'msg,with "quotes"\nand newline ' + i]));
      if (chunk.length === 10_000) { fs.writeSync(fd, chunk.join('')); chunk.length = 0; }
    }
    fs.closeSync(fd);
    global.gc?.();
    const before = process.memoryUsage().heapUsed;
    const r = await filterLogFile(p, path.join(dir, 'big.out.csv'), new Set(['005xx000000gstA']));
    const growth = process.memoryUsage().heapUsed - before;
    expect(r.totalRows).toBe(300_000);
    expect(r.guestRows).toBe(30_000);
    expect(growth).toBeLessThan(64 * 1024 * 1024);
  }, 60_000);
});
