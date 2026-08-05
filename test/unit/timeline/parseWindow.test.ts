import { describe, it, expect } from '@jest/globals';
import { parseWindow } from '../../../src/timeline/parseWindow.js';

/**
 * Turning an ISO 8601 interval into the hours to read off disk.
 *
 * Captures are stored per hour, so a window is only ever a set of hour files. Getting this wrong
 * is quiet: asking for one hour too few loses evidence that exists, and the timeline reports an
 * absence that the capture would have contradicted.
 */
describe('parseWindow', () => {
  it('expands a duration into the hours it covers', () => {
    expect(parseWindow('2026-08-02T04:00Z/PT1H')).toEqual({
      date: '2026-08-02',
      hours: ['04'],
      startMs: Date.parse('2026-08-02T04:00:00Z'),
      endMs: Date.parse('2026-08-02T05:00:00Z'),
    });
  });

  it('covers every hour of a multi-hour duration', () => {
    expect(parseWindow('2026-08-02T04:00Z/PT3H')).toMatchObject({
      date: '2026-08-02',
      hours: ['04', '05', '06'],
      endMs: Date.parse('2026-08-02T07:00:00Z'),
    });
  });

  it('accepts an explicit end instant', () => {
    expect(parseWindow('2026-08-02T04:00Z/2026-08-02T06:00Z')).toMatchObject({
      date: '2026-08-02',
      hours: ['04', '05'],
      startMs: Date.parse('2026-08-02T04:00:00Z'),
      endMs: Date.parse('2026-08-02T06:00:00Z'),
    });
  });

  it('includes the hour a partial duration lands in', () => {
    // 30 minutes from 04:00 stays inside hour 04; 90 minutes reaches into 05.
    expect(parseWindow('2026-08-02T04:00Z/PT30M').hours).toEqual(['04']);
    expect(parseWindow('2026-08-02T04:00Z/PT90M').hours).toEqual(['04', '05']);
  });

  it('includes the starting hour even when the window begins mid-hour', () => {
    // Evidence from 04:00–04:30 lives in the 04 file and would be lost by rounding up.
    expect(parseWindow('2026-08-02T04:45Z/PT30M').hours).toEqual(['04', '05']);
  });

  it('pads single-digit hours to match the stored file names', () => {
    expect(parseWindow('2026-08-02T04:00Z/PT1H').hours).toEqual(['04']);
    expect(parseWindow('2026-08-02T00:00Z/PT1H').hours).toEqual(['00']);
  });

  it('rejects a window that crosses midnight, and names the two runs that would cover it', () => {
    // The store is keyed by date, so a cross-day window needs more than one date. Refusing is
    // honest; quietly reading only the first day would under-report. Naming both dates saves
    // the reader working out what to run instead.
    expect(() => parseWindow('2026-08-02T23:00Z/PT2H')).toThrow(/one UTC day/i);
    expect(() => parseWindow('2026-08-02T23:00Z/PT2H')).toThrow(/2026-08-02[\s\S]*2026-08-03/);
  });

  it('answers malformed input with worked examples, not a grammar', () => {
    // The person reading this is mid-incident with a timestamp in front of them. Naming the
    // standard they failed to satisfy does not help; showing what to type does.
    let message = '';
    try { parseWindow('sometime last week'); } catch (e) { message = (e as Error).message; }

    expect(message).toMatch(/yesterday/i);
    expect(message).toContain('2026-08-02');
    expect(message).toMatch(/\b2h\b/);

    // A bare `PT` carries no duration. It is malformed rather than zero-length, so the reader
    // gets the forms back rather than a remark about window length. Anchored, because the
    // zero-length message also quotes the forms and an unanchored match cannot tell them apart.
    expect(() => parseWindow('2026-08-02T04:00Z/PT')).toThrow(/^Could not read that window/);
  });

  it('rejects an end that precedes its start', () => {
    expect(() => parseWindow('2026-08-02T06:00Z/2026-08-02T04:00Z')).toThrow(/not after its start/i);
  });

  it('rejects a zero-length window, which can only ever return nothing', () => {
    expect(() => parseWindow('2026-08-02T04:00Z/PT0H')).toThrow(/not after its start/i);
  });
});
