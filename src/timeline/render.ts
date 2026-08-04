import { EVENT_ROW_COLUMNS, type EventRow } from './EventRow.js';
import type { Refusal, Seed } from './CorrelationEngine.js';
import type { JoinKeyType } from './JoinKeys.js';
import type { CoverageAssessment } from './CaptureIndex.js';

export interface TimelineOutput {
  window: string;
  seeds: ReadonlyArray<Seed>;
  rows: ReadonlyArray<EventRow>;
  refusals: ReadonlyArray<Refusal>;
  expandedThrough: ReadonlyArray<{ type: JoinKeyType; value: string }>;
  coverage: CoverageAssessment;
}

/**
 * Chronological, and ours to impose.
 *
 * Real-time event queries reject an ORDER BY on the event date, so rows arrive in whatever order
 * each source happened to yield. A forensic timeline that is not in time order is not a timeline.
 */
function chronological(rows: ReadonlyArray<EventRow>): EventRow[] {
  return [...rows].sort((a, b) => (a.timestamp_utc ?? '').localeCompare(b.timestamp_utc ?? '') || a.seq - b.seq);
}

/**
 * RFC 4180 quoting.
 *
 * Values here are user-controlled — URIs, GraphQL queries, Aura messages — and any of them can
 * carry a comma, a quote or a newline. An unquoted newline turns one record into two, which in a
 * forensic export means inventing an event that never happened.
 */
function csvCell(value: unknown): string {
  if (value === undefined || value === null) return '';
  const text = String(value);
  if (!/[",\n\r]/.test(text)) return text;
  return `"${text.replace(/"/g, '""')}"`;
}

export function renderCsv(output: TimelineOutput): string {
  const lines = [EVENT_ROW_COLUMNS.join(',')];
  for (const row of chronological(output.rows)) {
    lines.push(EVENT_ROW_COLUMNS.map((column) => csvCell(row[column])).join(','));
  }
  // Trailing newline: every line is terminated, which is what POSIX text tools assume. Without
  // it `wc -l` reports one fewer line than the file holds, and a row count taken that way is
  // quietly wrong — in an evidence export that is a miscount someone may rely on.
  return lines.join('\n') + '\n';
}

/**
 * The machine-readable form, carrying the reasoning as well as the result.
 *
 * The rows alone are an assertion. Shipping the seeds, the keys actually expanded through and
 * every refusal alongside them makes the assertion checkable: a reviewer can see which hops the
 * conclusion rests on without re-running anything.
 */
export function renderJson(output: TimelineOutput): string {
  return JSON.stringify(
    {
      window: output.window,
      seeds: output.seeds,
      coverage: {
        state: output.coverage.state,
        missing: output.coverage.missing,
        capturedSources: output.coverage.capturedSources,
        statement: output.coverage.statement(output.rows.length),
      },
      expandedThrough: output.expandedThrough,
      refusals: output.refusals,
      rows: chronological(output.rows),
    },
    null,
    2,
  );
}

function countBy(rows: ReadonlyArray<EventRow>, pick: (r: EventRow) => string): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(pick(row), (counts.get(pick(row)) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function table(header: [string, string], rows: Array<[string, number]>): string {
  return [
    `| ${header[0]} | ${header[1]} |`,
    '|---|---:|',
    ...rows.map(([k, v]) => `| ${k} | ${v} |`),
  ].join('\n');
}

/**
 * The narrative form.
 *
 * Ordered so a reader meets the caveats before the findings. Coverage leads, because every count
 * below it means something different depending on what was captured, and a reader who has
 * already absorbed "89 rows" will not revise that impression when the caveat arrives later.
 */
export function renderSummary(output: TimelineOutput): string {
  const rows = chronological(output.rows);
  const sections: string[] = [];

  sections.push('# Timeline');
  sections.push(`**Window:** ${output.window}`);
  sections.push(
    `**Seeds:** ${output.seeds.map((s) => `${s.type}:${s.value}`).join(', ') || '(none — whole window)'}`,
  );

  sections.push('## Coverage');
  sections.push('```\n' + output.coverage.banner() + '\n```');
  sections.push(output.coverage.statement(rows.length));

  sections.push('## Rows by event type');
  sections.push(rows.length === 0 ? '_No rows._' : table(['Event type', 'Rows'], countBy(rows, (r) => r.event_type)));

  sections.push('## Rows by attribution');
  sections.push(
    rows.length === 0 ? '_No rows._' : table(['Tied in by', 'Rows'], countBy(rows, (r) => String(r.attribution))),
  );

  sections.push('## Expansions refused');
  if (output.refusals.length === 0) {
    // Stated rather than omitted: an investigator cannot tell an empty section from an
    // unwritten one, and "nothing was refused" is a materially different claim from silence.
    sections.push('No expansions were refused. Every key reached was within the cardinality threshold.');
  } else {
    sections.push(
      output.refusals
        .map(
          (r) =>
            `- \`${r.type}\` **${r.value}** is shared by ${r.cardinality} distinct addresses ` +
            `(threshold ${r.threshold}) — not expanded. Override with \`--allow-shared-identity\`.`,
        )
        .join('\n'),
    );
  }

  sections.push('## Did records leave');
  const withCounts = rows.filter((r) => r.rows_processed !== undefined || r.records_returned !== undefined);
  if (withCounts.length === 0) {
    // The honest answer to an unanswerable question. No EventLogFile type records what came
    // back, so silence here would let a reader infer "nothing left" from evidence that cannot
    // support it either way.
    sections.push(
      'Unanswerable from this capture — no real-time event rows were captured for this window, ' +
        'and no EventLogFile type records how many records a query returned.',
    );
  } else {
    sections.push(
      withCounts
        .map(
          (r) =>
            `- \`${r.event_type}\` at ${r.timestamp_utc} — Rows processed: ${r.rows_processed ?? '(not stated)'}` +
            `, Records returned: ${r.records_returned ?? '(not stated)'}`,
        )
        .join('\n'),
    );
  }

  return sections.join('\n\n') + '\n';
}
