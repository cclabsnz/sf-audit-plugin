import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadCaptures } from '../../../src/timeline/loadCaptures.js';
import { parseWindow } from '../../../src/timeline/parseWindow.js';

/**
 * Reading what `sf audit events pull` actually writes.
 *
 * The free tier serves Daily-interval logs, so the capture command's normal output is one file
 * per event type per day — `{EventType}/{date}-{id}.csv` — not the hourly form. A timeline that
 * only reads the hourly layout cannot see any of it, which makes the whole command unusable
 * against the captures it exists to read.
 *
 * A daily file also spans twenty-four hours, so selecting the file is not selecting the window.
 * Rows have to be filtered on their own timestamps, or asking for one hour returns the day.
 */
const ORG = '00Dxx0000000000EAA';

describe('loadCaptures — daily captures', () => {
  let dir: string;

  const write = (rel: string, body: string): void => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf-8');
  };

  const hour = (h: string, extra = ''): string =>
    `EVENT_TYPE,TIMESTAMP_DERIVED,CLIENT_IP${extra ? ',' + extra.split('=')[0] : ''}\n` +
    `URI,2026-08-02T${h}:30:00.000Z,203.0.113.50${extra ? ',' + extra.split('=')[1] : ''}\n`;

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'daily-cap-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const load = (interval: string) => {
    const w = parseWindow(interval);
    return loadCaptures({ base: dir, orgId: ORG, date: w.date, hours: w.hours, startMs: w.startMs, endMs: w.endMs });
  };

  it('reads the daily layout the capture command writes by default', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, hour('04'));

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.windowPresent).toBe(true);
    expect(loaded.rows).toHaveLength(1);
  });

  it('filters a daily file down to the requested window', () => {
    // One file, three hours of activity. Asking for one hour must not return the day.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`,
      'EVENT_TYPE,TIMESTAMP_DERIVED,CLIENT_IP\n' +
      'URI,2026-08-02T03:30:00.000Z,203.0.113.50\n' +
      'URI,2026-08-02T04:30:00.000Z,203.0.113.50\n' +
      'URI,2026-08-02T05:30:00.000Z,203.0.113.50\n');

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.rows[0].TIMESTAMP_DERIVED).toBe('2026-08-02T04:30:00.000Z');
  });

  it('treats the window as half-open, so an hour boundary belongs to one window only', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`,
      'EVENT_TYPE,TIMESTAMP_DERIVED\n' +
      'URI,2026-08-02T04:00:00.000Z\n' +
      'URI,2026-08-02T05:00:00.000Z\n');

    // Two consecutive one-hour windows must partition the rows, not double-count the boundary.
    expect(load('2026-08-02T04:00Z/PT1H').rows).toHaveLength(1);
    expect(load('2026-08-02T05:00Z/PT1H').rows).toHaveLength(1);
  });

  it('reads the compact timestamp when the derived one is absent', () => {
    // EventLogFile carries both; TIMESTAMP is Salesforce's own form and does not parse as ISO.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`,
      'EVENT_TYPE,TIMESTAMP\nURI,20260802043000.000\n');

    expect(load('2026-08-02T04:00Z/PT1H').rows).toHaveLength(1);
  });

  it('keeps a row whose time cannot be read, rather than losing it silently', () => {
    // Excluding it would drop evidence with no trace. Keeping it shows up in the output with an
    // empty timestamp, where a reviewer can see and judge it.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`,
      'EVENT_TYPE,TIMESTAMP_DERIVED\nURI,\nURI,2026-08-02T04:30:00.000Z\n');

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.rows).toHaveLength(2);
    expect(loaded.undated).toBe(1);
  });

  it('reports the window as present when the day was captured but the hour was quiet', () => {
    // The distinction the whole command turns on: captured-and-empty is not uncaptured.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, hour('09'));

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.windowPresent).toBe(true);
    expect(loaded.rows).toHaveLength(0);
  });

  it('reads daily and hourly captures for the same day together', () => {
    // A day can hold both: daily files from the free tier, hourly ones from a later pull.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, hour('04'));
    write(`${ORG}/AuraRequest/2026-08-02/04-0AT2.csv`, hour('04').replace('URI', 'AuraRequest'));

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.rows).toHaveLength(2);
    expect(new Set(loaded.rows.map((r) => r.EVENT_TYPE))).toEqual(new Set(['URI', 'AuraRequest']));
  });

  it('ignores a daily file for a different date', () => {
    write(`${ORG}/URI/2026-08-01-0AT1.csv`, 'EVENT_TYPE,TIMESTAMP_DERIVED\nURI,2026-08-01T04:30:00.000Z\n');

    expect(load('2026-08-02T04:00Z/PT1H').windowPresent).toBe(false);
  });

  it('still filters real-time rows to the window', () => {
    write(`${ORG}/_realtime/ListViewEvent/2026-08-02/04.ndjson`,
      '{"EventIdentifier":"in","EventDate":"2026-08-02T04:30:00.000Z"}\n' +
      '{"EventIdentifier":"out","EventDate":"2026-08-02T09:30:00.000Z"}\n');

    const loaded = load('2026-08-02T04:00Z/PT1H');

    expect(loaded.rows).toHaveLength(1);
    expect(loaded.rows[0].EventIdentifier).toBe('in');
  });
});

describe('parseWindow — instants for row filtering', () => {
  it('reports the window boundaries, not only the hours to read', () => {
    const w = parseWindow('2026-08-02T04:15Z/PT30M');

    expect(new Date(w.startMs).toISOString()).toBe('2026-08-02T04:15:00.000Z');
    expect(new Date(w.endMs).toISOString()).toBe('2026-08-02T04:45:00.000Z');
    // Still reads the whole hour file; the rows are then narrowed to the window.
    expect(w.hours).toEqual(['04']);
  });
});

describe('loadCaptures — a partial file is not a capture', () => {
  let dir: string;

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'partial-cap-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const write = (rel: string, body: string): void => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf-8');
  };

  const load = () => {
    const w = parseWindow('2026-08-02T04:00Z/PT1H');
    return loadCaptures({ base: dir, orgId: ORG, date: w.date, hours: w.hours, startMs: w.startMs, endMs: w.endMs });
  };

  it('does not treat a zero-byte file as a captured window', () => {
    // sf-core 0.3.0 made presence on disk mean complete: a run killed between create and write
    // leaves an empty file, and counting it as coverage would report a window as captured when
    // nothing was ever written to it. The reader has to agree with the writer about that, or a
    // gap the capture side now refuses to hide reappears here.
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, '');

    expect(load().windowPresent).toBe(false);
  });

  it('ignores an in-progress download rather than reading half a file', () => {
    // The atomic write leaves a .part file while a download is running. It is not a capture and
    // must not be read as one, least of all mid-write.
    write(`${ORG}/URI/2026-08-02-0AT1.csv.12345.part`, 'EVENT_TYPE\nURI\n');

    const loaded = load();
    expect(loaded.windowPresent).toBe(false);
    expect(loaded.rows).toHaveLength(0);
  });

  it('still reads a complete file sitting beside a partial one', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, '');
    write(`${ORG}/AuraRequest/2026-08-02-0AT2.csv`,
      'EVENT_TYPE,TIMESTAMP_DERIVED\nAuraRequest,2026-08-02T04:30:00.000Z\n');

    const loaded = load();
    expect(loaded.windowPresent).toBe(true);
    expect(loaded.rows).toHaveLength(1);
  });
});
