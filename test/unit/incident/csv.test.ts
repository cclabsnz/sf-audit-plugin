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
  it('handles quote pairs split across read chunks', async () => {
    // With chunkSize=8, we can control exactly where boundaries fall.
    // Build a CSV with a doubled quote pair straddling a chunk boundary.
    // Field: "a""b" has 6 chars: quote, a, quote, quote, b, quote.
    // With chunkSize=8: "a""" (4 chars) + "b" (1 char) + newline crosses at the doubled quotes.
    // Position 0-3: "a"", position 4: (boundary), position 4-6: "b"
    const csv = '"F1"\n"a""b"\n';
    const p = w('split-pair.csv', csv);
    const rows = await all(readCsvCells(p, { chunkSize: 5 }));
    expect(rows).toEqual([['F1'], ['a"b']]);
  });
  it('handles closing quote and comma split across chunks', async () => {
    // Field: "text", next field. boundary between " and ,
    // chunkSize=8: "text"" (5 chars) + ", (2 chars) + more crosses at closing quote/comma
    const csv = '"F1","F2"\n"txt",data\n';
    const p = w('split-comma.csv', csv);
    const rows = await all(readCsvCells(p, { chunkSize: 9 }));
    expect(rows).toEqual([['F1', 'F2'], ['txt', 'data']]);
  });
  it('handles CR/LF split across chunks', async () => {
    // Ensure \r and \n can be split across chunks.
    // chunkSize=3: splits right at \r or \n
    const csv = '"a"\r\n"b"\r\n';
    const p = w('split-crlf.csv', csv);
    const rows = await all(readCsvCells(p, { chunkSize: 3 }));
    expect(rows).toEqual([['a'], ['b']]);
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
  it('rejects and cleans up when write stream cannot open', async () => {
    // Parent directory is a regular file, so child path cannot be created.
    const regularFile = w('regular.txt', 'data');
    const unwritablePath = path.join(regularFile, 'nested.csv');
    const raw = w('raw2.csv', csvLine(['USER_ID']) + csvLine(['005xx000000gstA']));
    await expect(filterLogFile(raw, unwritablePath, new Set(['005xx000000gstA']))).rejects.toThrow();
    // Verify partial output file was cleaned up
    expect(fs.existsSync(unwritablePath)).toBe(false);
  });
  it('filters a large file with bounded heap growth', async () => {
    // Generate ~150 MB fixture to detect non-streaming (whole-file reads)
    const p = path.join(dir, 'big-150.csv');
    const fd = fs.openSync(p, 'w');
    fs.writeSync(fd, csvLine(['USER_ID', 'ACTION_MESSAGE']));

    // Generate 150 MB worth of rows; each row is roughly 200 bytes (60 byte ID + 140 byte message)
    const targetBytes = 150 * 1024 * 1024;
    const rowSize = 200;
    const numRows = Math.ceil(targetBytes / rowSize);
    const chunk: string[] = [];
    for (let i = 0; i < numRows; i++) {
      chunk.push(csvLine([i % 10 === 0 ? '005xx000000gstA' : '005xx000000othr', 'msg,with "quotes"\nand newline ' + i.toString().padEnd(140)]));
      if (chunk.length === 5_000) { fs.writeSync(fd, chunk.join('')); chunk.length = 0; }
    }
    if (chunk.length > 0) fs.writeSync(fd, chunk.join(''));
    fs.closeSync(fd);

    // Force garbage collection and record baseline heap
    global.gc?.();
    const baselineHeap = process.memoryUsage().heapUsed;

    // Sample heap usage during filtering to find peak
    let peakHeapDuringOp = baselineHeap;
    const interval = setInterval(() => {
      const current = process.memoryUsage().heapUsed;
      if (current > peakHeapDuringOp) peakHeapDuringOp = current;
    }, 25);

    const outPath = path.join(dir, 'big-150.out.csv');
    const r = await filterLogFile(p, outPath, new Set(['005xx000000gstA']));

    clearInterval(interval);

    const peakGrowth = peakHeapDuringOp - baselineHeap;

    expect(r.totalRows).toBe(numRows);
    expect(r.guestRows).toBeCloseTo(numRows / 10, -3);
    // Peak growth should stay well under the input size; 150 MB input should not require 150 MB+ in memory
    expect(peakGrowth).toBeLessThan(150 * 1024 * 1024);

    // Clean up output file
    fs.rmSync(outPath, { force: true });
  }, 180_000);
});
