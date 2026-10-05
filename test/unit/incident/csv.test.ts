import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as v8 from 'node:v8';
import * as vm from 'node:vm';
import { readCsvCells, readCsvRecords, csvLine, filterLogFile } from '../../../src/incident/csv.js';

v8.setFlagsFromString('--expose_gc');
const forceGc = vm.runInNewContext('gc') as () => void;
const live = () => { forceGc(); return process.memoryUsage().heapUsed; };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-csv-'));
const w = (name: string, body: string) => { const p = path.join(dir, name); fs.writeFileSync(p, body); return p; };
async function all<T>(g: AsyncIterable<T>): Promise<T[]> { const out: T[] = []; for await (const x of g) out.push(x); return out; }

describe('readCsvCells', () => {
  it('handles quoted commas, doubled quotes, CRLF and newlines inside fields', async () => {
    const p = w('q.csv', '"A","B"\r\n"x,1","he said ""hi"""\r\n"line1\nline2",""\r\n');
    expect(await all(readCsvCells(p))).toEqual([['A', 'B'], ['x,1', 'he said "hi"'], ['line1\nline2', '']]);
  });
  it('handles doubled quotes split across chunks at bytes 7–8', async () => {
    const input = '"A"\n"ab""c"\n';
    // Chunk 0: bytes 0-7 = '"A"\n"ab"'
    // Chunk 1: bytes 8+ = '"c"\n'
    // Boundary straddles the doubled quote pair
    expect(input[7]).toBe('"');
    expect(input[8]).toBe('"');
    const p = w('split-pair.csv', input);
    const rows = await all(readCsvCells(p, { chunkSize: 8 }));
    expect(rows).toEqual([['A'], ['ab"c']]);
  });
  it('handles closing quote and comma split across chunks at bytes 15–16', async () => {
    const input = '"A","B"\n"xyzabc","q"\n';
    // Chunk 0: bytes 0-15 = '"A","B"\n"xyzabc"'
    // Chunk 1: bytes 16+ = ',"q"\n'
    // Boundary straddles the closing quote and comma
    expect(input[15]).toBe('"');
    expect(input[16]).toBe(',');
    const p = w('split-comma.csv', input);
    const rows = await all(readCsvCells(p, { chunkSize: 16 }));
    expect(rows).toEqual([['A', 'B'], ['xyzabc', 'q']]);
  });
  it('handles CR/LF split across chunks', async () => {
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
  it('rejects with EISDIR when output path is a directory, with 10s timeout', async () => {
    // Create a directory at the output path; mkdir(dirname) succeeds, but createWriteStream emits EISDIR.
    const outDir = path.join(dir, 'dir-out-' + Date.now());
    fs.mkdirSync(outDir);
    const raw = w('raw2.csv', csvLine(['USER_ID']) + csvLine(['005xx000000gstA']));

    // Use timeout to fail if the call hangs
    let completed = false;
    const timeoutPromise = new Promise<void>((_, reject) =>
      setTimeout(() => !completed && reject(new Error('filterLogFile hung')), 10000)
    );

    const filterPromise = filterLogFile(raw, outDir, new Set(['005xx000000gstA'])).then(
      () => { completed = true; },
      (err) => { completed = true; throw err; }
    );

    await expect(Promise.race([filterPromise, timeoutPromise])).rejects.toMatchObject({ code: 'EISDIR' });
  });
  it('streams a file far larger than the live-heap bound', async () => {
    const LIMIT = 64 * 1024 * 1024; // live heap may not grow by more than 64 MiB
    const input = path.join(dir, 'huge.csv');
    const output = path.join(dir, 'huge.out.csv');

    // Generate 256+ MB fixture
    const fd = fs.openSync(input, 'w');
    fs.writeSync(fd, csvLine(['USER_ID', 'ACTION_MESSAGE']));
    const targetBytes = 260 * 1024 * 1024;
    const rowSize = 195;
    const numRows = Math.ceil(targetBytes / rowSize);
    const chunk: string[] = [];
    for (let i = 0; i < numRows; i++) {
      chunk.push(csvLine([i % 10 === 0 ? '005xx000000gstA' : '005xx000000othr', 'msg,with "quotes"\nand newline ' + i.toString().padEnd(140)]));
      if (chunk.length === 10_000) { fs.writeSync(fd, chunk.join('')); chunk.length = 0; }
    }
    if (chunk.length > 0) fs.writeSync(fd, chunk.join(''));
    fs.closeSync(fd);

    expect(fs.statSync(input).size).toBeGreaterThan(256 * 1024 * 1024);
    const base = live();
    let peak = 0;
    const timer = setInterval(() => { peak = Math.max(peak, live() - base); }, 250);
    try {
      const r = await filterLogFile(input, output, new Set(['005xx000000gstA']));
      peak = Math.max(peak, live() - base);
      expect(r.totalRows).toBe(numRows);
      if (peak >= LIMIT) throw new Error(`live heap grew ${(peak / 1048576).toFixed(1)} MiB`);
    } finally {
      clearInterval(timer);
      fs.rmSync(input, { force: true });
      fs.rmSync(output, { force: true });
    }
  }, 300_000);
});
