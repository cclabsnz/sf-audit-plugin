// Pure helpers for the `audit events pull` command. Kept free of I/O so they are
// unit-testable without an org connection or the oclif command harness.

export interface EventLogQueryOptions {
  /** Number of days of LogDate to request (LAST_N_DAYS:N). */
  since: number;
  /** Optional EventType allow-list (already sanitised or not — we sanitise again). */
  types?: string[];
}

/**
 * Reduce free-form `--types` input to safe EventType tokens. EventTypes are PascalCase
 * identifiers (Login, ApiTotalUsage, LightningError, …), so we strip anything that is not
 * alphanumeric. This doubles as the SOQL-injection guard for the IN clause.
 */
export function sanitizeTypes(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((t) => t.replace(/[^A-Za-z0-9]/g, '').trim())
    .filter((t) => t.length > 0);
}

/** Normalise a Salesforce LogDate (datetime) to a YYYY-MM-DD string for filenames. */
export function toLogDate(raw: string): string {
  return String(raw).slice(0, 10);
}

/**
 * Build the read-only EventLogFile discovery query. `Interval = 'Daily'` excludes the paid
 * hourly logs; `LogDate = LAST_N_DAYS:N` bounds the window. `since` is coerced to a
 * non-negative integer and `types` are sanitised, so the interpolated string is injection-safe.
 */
export function buildEventLogQuery(opts: EventLogQueryOptions): string {
  const since = Math.max(0, Math.trunc(opts.since));
  const types = (opts.types ?? []).filter((t) => t.length > 0);
  const typeClause =
    types.length > 0 ? ` AND EventType IN (${types.map((t) => `'${t}'`).join(', ')})` : '';
  return (
    'SELECT Id, EventType, LogDate, LogFileLength, Interval, LogFileFieldNames ' +
    'FROM EventLogFile ' +
    `WHERE Interval = 'Daily' AND LogDate = LAST_N_DAYS:${since}${typeClause} ` +
    'ORDER BY LogDate'
  );
}
