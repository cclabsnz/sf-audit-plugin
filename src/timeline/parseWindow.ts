export interface Window {
  /** UTC date, YYYY-MM-DD. */
  date: string;
  /** Two-digit UTC hours to read, ascending. */
  hours: string[];
}

const FORM = 'Expected an ISO 8601 interval: <start>/<duration> or <start>/<end>, e.g. 2026-08-02T04:00Z/PT1H';

/** `PT90M`, `PT2H`, `PT1H30M` — the subset that makes sense for an hour-scale window. */
function durationMs(text: string): number | undefined {
  const match = /^PT(?:(\d+)H)?(?:(\d+)M)?$/.exec(text);
  if (!match || (match[1] === undefined && match[2] === undefined)) return undefined;
  return (Number(match[1] ?? 0) * 60 + Number(match[2] ?? 0)) * 60_000;
}

/**
 * Resolve a window to the hour files that hold it.
 *
 * Captures are stored one file per hour, so this is the step that decides what gets read. It
 * errs toward reading more rather than less: a window starting at 04:45 still reads hour 04,
 * because the evidence between 04:45 and 05:00 lives in that file and rounding up would drop it
 * silently. Over-reading costs a few rows the correlation then ignores; under-reading reports an
 * absence the capture would have contradicted.
 */
export function parseWindow(interval: string): Window {
  const parts = interval.split('/');
  if (parts.length !== 2) throw new Error(FORM);

  const [startText, endText] = parts;
  const start = new Date(startText);
  if (Number.isNaN(start.getTime())) throw new Error(FORM);

  let end: Date;
  const ms = durationMs(endText);
  if (ms !== undefined) {
    end = new Date(start.getTime() + ms);
  } else {
    end = new Date(endText);
    if (Number.isNaN(end.getTime())) throw new Error(FORM);
  }

  if (end.getTime() <= start.getTime()) {
    throw new Error(`Window end is not after its start — a zero or negative window can only return nothing. ${FORM}`);
  }

  const date = start.toISOString().slice(0, 10);
  // The store keys files by date, so a window spanning two of them needs two roots. Refusing is
  // honest; reading only the first day would under-report without saying so.
  const endBoundary = new Date(end.getTime() - 1);
  if (endBoundary.toISOString().slice(0, 10) !== date) {
    throw new Error('Window must fall within a single UTC day; split a cross-midnight window into two runs.');
  }

  const firstHour = start.getUTCHours();
  const lastHour = endBoundary.getUTCHours();
  const hours: string[] = [];
  for (let h = firstHour; h <= lastHour; h++) hours.push(String(h).padStart(2, '0'));

  return { date, hours };
}
