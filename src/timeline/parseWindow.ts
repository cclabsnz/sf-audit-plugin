export interface Window {
  /** UTC date, YYYY-MM-DD. */
  date: string;
  /** Two-digit UTC hours to read, ascending. */
  hours: string[];
  /** Window start, inclusive. */
  startMs: number;
  /** Window end, exclusive — so consecutive windows partition rows rather than sharing a boundary. */
  endMs: number;
}

/**
 * What to say when the input cannot be read.
 *
 * Worked examples rather than a grammar. "Expected an ISO 8601 interval" says what somebody got
 * wrong without saying what to type, and the person reading it is mid-incident with a timestamp
 * in front of them rather than a specification.
 */
const FORMS = [
  'Could not read that window. Any of these work:',
  '',
  '  yesterday                            the whole of yesterday, UTC',
  '  today                                midnight UTC until now',
  '  2026-08-02                           that whole day',
  '  2026-08-02T04:17Z                    the hour containing that instant',
  '  2h            90m                    the last two hours; the last ninety minutes',
  '  2026-08-02T04:00Z/PT1H               an exact interval — start and duration',
  '  2026-08-02T04:00Z/2026-08-02T06:00Z  an exact interval — start and end',
  '',
  'Times are UTC, and a window has to fall inside one UTC day.',
].join('\n');

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const LOOKBACK = /^(\d+)\s*(h|m)$/i;
/** `PT90M`, `PT2H`, `PT1H30M` — the subset that makes sense for an hour-scale window. */
const ISO_DURATION = /^PT(?:(\d+)H)?(?:(\d+)M)?$/;

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function durationMs(text: string): number | undefined {
  const match = ISO_DURATION.exec(text.trim());
  if (!match || (match[1] === undefined && match[2] === undefined)) return undefined;
  return (Number(match[1] ?? 0) * 60 + Number(match[2] ?? 0)) * 60_000;
}

/**
 * Read an instant, assuming UTC when no zone is given.
 *
 * Every capture is stored in UTC, so a bare timestamp is meant as UTC — reading it as local time
 * would shift the window by hours and return the wrong evidence without saying anything. A space
 * in place of the `T` is accepted because that is how a timestamp arrives when pasted out of a
 * report or a chat message.
 */
function instant(text: string): number | undefined {
  const normalised = text.trim().replace(' ', 'T');
  if (normalised === '') return undefined;
  const zoned = /(Z|[+-]\d{2}:?\d{2})$/.test(normalised) ? normalised : `${normalised}Z`;
  const parsed = Date.parse(zoned);
  return Number.isNaN(parsed) ? undefined : parsed;
}

const startOfDayMs = (ms: number): number => Date.parse(`${new Date(ms).toISOString().slice(0, 10)}T00:00:00Z`);

/**
 * Resolve a window to the hour files that hold it.
 *
 * Several spellings, one meaning. The exact ISO interval is precise and nobody composes one
 * under pressure; an investigator knows "yesterday", "the last two hours", or has a timestamp
 * pasted from an alert. Translating that by hand is a step where the timezone or the duration
 * syntax goes wrong, and the resulting empty timeline reads as an absence of evidence rather
 * than as a mistyped window.
 *
 * Resolution errs toward reading more rather than less: a window starting at 04:45 still reads
 * hour 04, because the evidence between 04:45 and 05:00 lives in that file. Over-reading costs a
 * few rows the correlation ignores; under-reading reports an absence the capture would have
 * contradicted.
 *
 * `now` is a parameter rather than read from the clock, so the relative forms are testable and a
 * run can be reproduced.
 */
export function parseWindow(interval: string, now: number = Date.now()): Window {
  const text = interval.trim();
  const lookback = LOOKBACK.exec(text);
  let startMs: number;
  let endMs: number;

  if (/^today$/i.test(text)) {
    startMs = startOfDayMs(now);
    endMs = now;
  } else if (/^yesterday$/i.test(text)) {
    startMs = startOfDayMs(now) - DAY_MS;
    endMs = startOfDayMs(now);
  } else if (lookback) {
    startMs = now - Number(lookback[1]) * (lookback[2].toLowerCase() === 'h' ? HOUR_MS : 60_000);
    endMs = now;
  } else if (DATE_ONLY.test(text)) {
    startMs = Date.parse(`${text}T00:00:00Z`);
    endMs = startMs + DAY_MS;
  } else if (text.includes('/')) {
    const [startText, endText] = text.split('/');
    const start = instant(startText);
    if (start === undefined) throw new Error(FORMS);
    startMs = start;

    const ms = durationMs(endText);
    if (ms !== undefined) {
      endMs = startMs + ms;
    } else {
      const end = instant(endText);
      if (end === undefined) throw new Error(FORMS);
      endMs = end;
    }
  } else {
    // A bare timestamp means the hour containing it — what somebody pastes off a log line or an
    // alert, where the window they want is the surrounding hour rather than the instant.
    const at = instant(text);
    if (at === undefined) throw new Error(FORMS);
    startMs = at - (at % HOUR_MS);
    endMs = startMs + HOUR_MS;
  }

  if (endMs <= startMs) {
    throw new Error(
      `Window end is not after its start — a zero or negative window can only return nothing.\n\n${FORMS}`,
    );
  }

  const date = new Date(startMs).toISOString().slice(0, 10);
  const endBoundary = new Date(endMs - 1);
  // The store keys files by date, so a window spanning two of them needs two roots. Refusing is
  // honest, and it names the two runs that would cover it; reading only the first day would
  // under-report without saying so.
  if (endBoundary.toISOString().slice(0, 10) !== date) {
    throw new Error(
      'A window has to fall inside one UTC day, and this one crosses midnight.\n' +
        `Run it twice — once for ${date}, once for ${endBoundary.toISOString().slice(0, 10)} — or narrow it.`,
    );
  }

  const firstHour = new Date(startMs).getUTCHours();
  const lastHour = endBoundary.getUTCHours();
  const hours: string[] = [];
  for (let h = firstHour; h <= lastHour; h++) hours.push(String(h).padStart(2, '0'));

  return { date, hours, startMs, endMs };
}
