import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { correlate } from '../../../src/timeline/CorrelationEngine.js';
import { describeCaptures } from '../../../src/timeline/loadCaptures.js';

/**
 * Two ways somebody gets stuck, and neither is their fault.
 *
 * They do not know what to seed on. An investigation often starts with a window and a suspicion
 * rather than an address, and a command that returns nothing without a seed teaches them
 * nothing — the whole window, uncorrelated, is where you look to find the seed.
 *
 * They do not know which windows exist. The captures are on their disk, and "no captures for
 * that window" sends them to re-pull data that may already be there under a different date.
 * The store knows the answer and should say it.
 */
describe('correlate — no seed means the whole window', () => {
  const rows = [
    { EVENT_TYPE: 'A', CLIENT_IP: '203.0.113.1', REQUEST_ID: 'r1' },
    { EVENT_TYPE: 'B', CLIENT_IP: '203.0.113.2', REQUEST_ID: 'r2' },
    { EVENT_TYPE: 'C', USER_ID: 'u1' },
  ];

  it('returns every row rather than nothing', () => {
    // Spec: omitted seed means the whole window, normalised but uncorrelated. Returning an
    // empty timeline instead reads as "nothing happened", which is the opposite of the truth.
    expect(correlate(rows, [], {}).rows).toHaveLength(3);
  });

  it('marks the rows as unfiltered rather than claiming a seed matched them', () => {
    const result = correlate(rows, [], {});

    expect([...new Set(result.rows.map((r) => r.attribution))]).toEqual(['window']);
  });

  it('expands through nothing, because there is nothing to expand from', () => {
    const result = correlate(rows, [], {});

    expect(result.expandedThrough).toEqual([]);
    expect(result.refusals).toEqual([]);
  });

  it('still returns every row when a shared identity would otherwise be refused', () => {
    // The gate exists to stop expansion inventing attribution. With no seed there is no
    // attribution to invent, so nothing should be withheld.
    const crowd = Array.from({ length: 50 }, (_, i) => ({
      EVENT_TYPE: 'X', CLIENT_IP: `203.0.113.${i}`, USER_ID: 'guest',
    }));

    expect(correlate(crowd, [], {}).rows).toHaveLength(50);
  });
});

describe('describeCaptures', () => {
  let dir: string;
  const ORG = '00Dxx0000000000EAA';

  const write = (rel: string, body = 'EVENT_TYPE\nX\n'): void => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf-8');
  };

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'describe-cap-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('lists the dates that have captures', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`);
    write(`${ORG}/URI/2026-08-01-0AT2.csv`);

    expect(describeCaptures(dir, ORG).map((d) => d.date)).toEqual(['2026-08-01', '2026-08-02']);
  });

  it('counts the event types captured on each date', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`);
    write(`${ORG}/Login/2026-08-02-0AT2.csv`);
    write(`${ORG}/URI/2026-08-01-0AT3.csv`);

    const days = describeCaptures(dir, ORG);
    expect(days.find((d) => d.date === '2026-08-02')!.types).toBe(2);
    expect(days.find((d) => d.date === '2026-08-01')!.types).toBe(1);
  });

  it('finds dates captured in the hourly layout too', () => {
    write(`${ORG}/AuraRequest/2026-08-03/04-0AT1.csv`);

    const day = describeCaptures(dir, ORG).find((d) => d.date === '2026-08-03');
    expect(day).toBeDefined();
    expect(day!.hours).toEqual(['04']);
  });

  it('reports no hours for a daily capture, which covers the whole day', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`);

    expect(describeCaptures(dir, ORG).find((d) => d.date === '2026-08-02')!.hours).toEqual([]);
  });

  it('includes real-time captures', () => {
    write(`${ORG}/_realtime/ListViewEvent/2026-08-04/09.ndjson`, '{"a":1}\n');

    const day = describeCaptures(dir, ORG).find((d) => d.date === '2026-08-04');
    expect(day).toBeDefined();
    expect(day!.hours).toEqual(['09']);
  });

  it('ignores an empty file, matching what counts as captured elsewhere', () => {
    write(`${ORG}/URI/2026-08-02-0AT1.csv`, '');

    expect(describeCaptures(dir, ORG)).toEqual([]);
  });

  it('returns nothing for an org with no captures, without throwing', () => {
    expect(describeCaptures(dir, '00Dxx0000000009EAA')).toEqual([]);
  });
});
