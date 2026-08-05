import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseCsv, loadCaptures } from '../../../src/timeline/loadCaptures.js';

/**
 * Reading back what the capture wrote.
 *
 * Two properties matter more than completeness here. The parser must be a real CSV parser,
 * because event log values carry commas, quotes and newlines — a GraphQL query in a column will
 * split a naive reader's row in half and shift every field after it. And loading must be
 * fault-tolerant: one malformed file cannot lose the rest of the window, for the same reason the
 * capture writes files verbatim rather than transforming them.
 */
describe('parseCsv', () => {
  it('maps each row against the header', () => {
    expect(parseCsv('A,B\n1,2\n')).toEqual([{ A: '1', B: '2' }]);
  });

  it('reads a quoted field containing a comma', () => {
    expect(parseCsv('A,B\n"x,y",2')).toEqual([{ A: 'x,y', B: '2' }]);
  });

  it('reads doubled quotes as one literal quote', () => {
    expect(parseCsv('A\n"say ""hi"""')).toEqual([{ A: 'say "hi"' }]);
  });

  it('reads a quoted field spanning newlines without splitting the row', () => {
    // This is the case that breaks a split-on-newline reader, and GraphQL columns hit it.
    const rows = parseCsv('A,B\n"query {\n  a\n}",2');

    expect(rows).toHaveLength(1);
    expect(rows[0].A).toBe('query {\n  a\n}');
    expect(rows[0].B).toBe('2');
  });

  it('handles CRLF line endings', () => {
    expect(parseCsv('A,B\r\n1,2\r\n')).toEqual([{ A: '1', B: '2' }]);
  });

  it('ignores a trailing newline rather than emitting a blank row', () => {
    expect(parseCsv('A\n1\n\n')).toEqual([{ A: '1' }]);
  });

  it('tolerates a row with fewer cells than the header', () => {
    // Truncated rows happen in real exports; the row is still evidence.
    expect(parseCsv('A,B,C\n1,2')).toEqual([{ A: '1', B: '2', C: '' }]);
  });

  it('tolerates a row with more cells than the header without corrupting known columns', () => {
    expect(parseCsv('A,B\n1,2,3')).toEqual([{ A: '1', B: '2' }]);
  });

  it('returns nothing for an empty file', () => {
    expect(parseCsv('')).toEqual([]);
    expect(parseCsv('A,B\n')).toEqual([]);
  });
});

describe('loadCaptures', () => {
  let dir: string;

  const write = (rel: string, body: string): void => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf-8');
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'timeline-load-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const ORG = '00Dxx0000000000EAA';

  it('reads hourly EventLogFile captures for the window', () => {
    write(`${ORG}/AuraRequest/2026-08-02/04-0AT1.csv`, 'EVENT_TYPE,CLIENT_IP\nAuraRequest,203.0.113.50\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.rows[0]).toMatchObject({ EVENT_TYPE: 'AuraRequest', CLIENT_IP: '203.0.113.50' });
  });

  it('records which file each row came from, so a finding can be traced back', () => {
    write(`${ORG}/URI/2026-08-02/04-0AT9.csv`, 'EVENT_TYPE\nURI\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(String(loaded.rows[0].__sourceFile)).toContain('04-0AT9.csv');
  });

  it('reads real-time NDJSON captures alongside the EventLogFile ones', () => {
    write(`${ORG}/AuraRequest/2026-08-02/04-0AT1.csv`, 'EVENT_TYPE\nAuraRequest\n');
    write(`${ORG}/_realtime/ListViewEvent/2026-08-02/04.ndjson`,
      '{"EventIdentifier":"evt-1","RowsProcessed":0}\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(2);
    const rte = loaded.rows.find((r) => r.EventIdentifier === 'evt-1')!;
    expect(rte.RowsProcessed).toBe(0);
    expect(rte.__source).toBe('RealTimeEventMonitoring');
  });

  it('skips a corrupt NDJSON line and keeps the rest of the file', () => {
    write(`${ORG}/_realtime/ListViewEvent/2026-08-02/04.ndjson`,
      '{"EventIdentifier":"evt-1"}\nnot json\n{"EventIdentifier":"evt-2"}\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(2);
    expect(loaded.malformed).toBe(1);
  });

  it('counts a JSON line that is not an object as malformed rather than storing it', () => {
    // Valid JSON, wrong shape. A bare number or string parses cleanly and would otherwise be
    // spread into a row, producing an event with no fields that still counts toward the total.
    write(`${ORG}/_realtime/ListViewEvent/2026-08-02/04.ndjson`,
      '{"EventIdentifier":"evt-1"}\n123\n"a string"\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.malformed).toBe(2);
  });

  it('reports the window as present once any capture file is found', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nA\n');

    expect(loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] }).windowPresent).toBe(true);
  });

  it('reports the window as present when only real-time rows were captured', () => {
    // An hour with no EventLogFile coverage is still a captured hour, and calling it absent
    // would send an operator to re-pull data that is already there.
    write(`${ORG}/_realtime/ListViewEvent/2026-08-02/04.ndjson`, '{"EventIdentifier":"evt-1"}\n');

    expect(loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] }).windowPresent).toBe(true);
  });

  it('keeps going when one file cannot be read at all', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nA\n');
    // A directory where a CSV is expected — unreadable as a file.
    fs.mkdirSync(path.join(dir, ORG, 'B', '2026-08-02', '04-2.csv'), { recursive: true });

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.unreadable).toBe(1);
  });

  it('reads only the hours asked for', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nInWindow\n');
    write(`${ORG}/A/2026-08-02/05-1.csv`, 'EVENT_TYPE\nOutOfWindow\n');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.rows[0].EVENT_TYPE).toBe('InWindow');
  });

  it('reports an absent window rather than pretending it was empty', () => {
    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.rows).toHaveLength(0);
    expect(loaded.windowPresent).toBe(false);
  });

  it('finds the most recent coverage manifest', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nA\n');
    write(`${ORG}/_manifests/coverage-1000-aaa.json`, JSON.stringify({
      orgId: ORG, capturedAt: 'early', interval: 'Hourly',
      elf: { requestedTypes: [], captured: [], skipped: [], failed: [] },
      rte: { captured: [], unavailable: [] }, accessErrors: [],
    }));
    write(`${ORG}/_manifests/coverage-2000-bbb.json`, JSON.stringify({
      orgId: ORG, capturedAt: 'late', interval: 'Hourly',
      elf: { requestedTypes: [], captured: [], skipped: [], failed: [] },
      rte: { captured: [], unavailable: [] }, accessErrors: [],
    }));

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.coverage?.capturedAt).toBe('late');
  });

  it('returns no coverage when no manifest exists, rather than inventing one', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nA\n');

    expect(loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] }).coverage).toBeUndefined();
  });

  it('ignores a manifest that is not valid JSON instead of failing the load', () => {
    write(`${ORG}/A/2026-08-02/04-1.csv`, 'EVENT_TYPE\nA\n');
    write(`${ORG}/_manifests/coverage-3000-ccc.json`, 'not json');

    const loaded = loadCaptures({ base: dir, orgId: ORG, date: '2026-08-02', hours: ['04'] });

    expect(loaded.coverage).toBeUndefined();
    expect(loaded.rows).toHaveLength(1);
  });
});
