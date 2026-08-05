import { describe, it, expect } from '@jest/globals';
import { parseWindow } from '../../../src/timeline/parseWindow.js';

/**
 * Windows a person can type.
 *
 * `2026-08-02T04:00Z/PT1H` is precise and nobody wants to compose one under pressure. An
 * investigator knows "yesterday", "the last two hours", or a date — and having to translate that
 * into an ISO 8601 interval is a step where they will get the timezone wrong, or the duration
 * syntax, and read the resulting empty timeline as an absence of evidence.
 *
 * The precise form still works. These are additional spellings of the same thing, so nothing
 * scripted against the ISO form has to change.
 */
const NOW = Date.parse('2026-08-04T09:30:00Z');

describe('parseWindow — a bare date means that whole day', () => {
  it('accepts a date on its own', () => {
    const w = parseWindow('2026-08-02', NOW);

    expect(w.date).toBe('2026-08-02');
    expect(new Date(w.startMs).toISOString()).toBe('2026-08-02T00:00:00.000Z');
    expect(new Date(w.endMs).toISOString()).toBe('2026-08-03T00:00:00.000Z');
  });

  it('reads every hour of that day', () => {
    expect(parseWindow('2026-08-02', NOW).hours).toHaveLength(24);
  });

  it('matches how the free tier captures — one file per day', () => {
    // Daily-interval logs are the common case, so the whole-day window is the one that lines up
    // with what is actually on disk.
    expect(parseWindow('2026-08-02', NOW).hours[0]).toBe('00');
    expect(parseWindow('2026-08-02', NOW).hours[23]).toBe('23');
  });
});

describe('parseWindow — words a person actually uses', () => {
  it('understands today', () => {
    expect(parseWindow('today', NOW).date).toBe('2026-08-04');
  });

  it('understands yesterday', () => {
    expect(parseWindow('yesterday', NOW).date).toBe('2026-08-03');
  });

  it('is case-insensitive and tolerates surrounding space', () => {
    expect(parseWindow('  Yesterday ', NOW).date).toBe('2026-08-03');
  });
});

describe('parseWindow — a duration back from now', () => {
  it('understands a number of hours', () => {
    const w = parseWindow('2h', NOW);

    expect(new Date(w.startMs).toISOString()).toBe('2026-08-04T07:30:00.000Z');
    expect(new Date(w.endMs).toISOString()).toBe('2026-08-04T09:30:00.000Z');
  });

  it('understands minutes', () => {
    expect(new Date(parseWindow('90m', NOW).startMs).toISOString()).toBe('2026-08-04T08:00:00.000Z');
  });

  it('reads the hours the window actually spans', () => {
    expect(parseWindow('2h', NOW).hours).toEqual(['07', '08', '09']);
  });

  it('refuses a lookback that would cross midnight, and says why', () => {
    // The store is keyed by date. Rather than silently returning part of the answer, it names
    // the constraint and the two runs that would cover it.
    expect(() => parseWindow('24h', NOW)).toThrow(/one UTC day/i);
  });
});

describe('parseWindow — a bare timestamp means the hour containing it', () => {
  it('expands an instant to its hour', () => {
    // The natural thing to paste is the timestamp off a log line or an alert.
    const w = parseWindow('2026-08-02T04:17:33Z', NOW);

    expect(new Date(w.startMs).toISOString()).toBe('2026-08-02T04:00:00.000Z');
    expect(new Date(w.endMs).toISOString()).toBe('2026-08-02T05:00:00.000Z');
  });

  it('accepts a space instead of the T, as pasted from a report', () => {
    expect(parseWindow('2026-08-02 04:17', NOW).hours).toEqual(['04']);
  });

  it('assumes UTC when no zone is given, because every capture is UTC', () => {
    expect(new Date(parseWindow('2026-08-02T04:00', NOW).startMs).toISOString()).toBe('2026-08-02T04:00:00.000Z');
  });
});

describe('parseWindow — the precise form still works', () => {
  it('accepts the ISO interval unchanged', () => {
    const w = parseWindow('2026-08-02T04:00Z/PT1H', NOW);

    expect(w.hours).toEqual(['04']);
    expect(new Date(w.endMs).toISOString()).toBe('2026-08-02T05:00:00.000Z');
  });
});

describe('parseWindow — unhelpful input gets a helpful error', () => {
  it('shows the forms it accepts rather than only naming a standard', () => {
    // "Expected an ISO 8601 interval" tells someone what they got wrong and not what to type.
    let message = '';
    try { parseWindow('last tuesday', NOW); } catch (e) { message = (e as Error).message; }

    expect(message).toContain('2026-08-02');   // a worked example, not a grammar
    expect(message).toMatch(/yesterday/i);
    expect(message).toMatch(/2h/);
  });
});
