import type { CaptureCoverage, SkipReason } from '@cclabsnz/sf-core';

export interface CoverageInput {
  /** The manifest for the window, or `undefined` when none was found. */
  coverage: CaptureCoverage | undefined;
}

/** A source that was asked for and is not in the data. */
export interface MissingSource {
  source: string;
  reason: SkipReason | string;
}

export type CoverageState = 'complete' | 'incomplete' | 'unknown';

export interface CoverageAssessment {
  state: CoverageState;
  missing: MissingSource[];
  capturedSources: string[];
  /** The sentence that qualifies a row count. Never composed by the caller. */
  statement(rowCount: number): string;
  /** The multi-line header every output leads with. */
  banner(): string;
}

/**
 * A skip that means the data is present, not absent.
 *
 * Dedup on a re-run reports the type as skipped because it was already pulled — the rows are on
 * disk from an earlier capture, so treating this as missing coverage would report a gap that
 * does not exist and push an operator into re-pulling data they already have.
 */
const SKIP_MEANS_PRESENT: ReadonlySet<string> = new Set<SkipReason>(['already-captured']);

/**
 * Decide what the capture actually covers, and say so in words the reader cannot misread.
 *
 * This is the most important behaviour in the command. Every other part can be wrong and look
 * wrong; this one can be wrong and look like reassurance. "No rows matched" means either the
 * actor did nothing or nobody captured the hour — and those are opposite conclusions in an
 * investigation.
 *
 * The wording therefore belongs here, derived from state, rather than being left to whichever
 * renderer happens to be printing. A caller cannot accidentally report an unqualified absence,
 * because it never gets to phrase one.
 */
export function assessCoverage(input: CoverageInput): CoverageAssessment {
  const { coverage } = input;

  if (!coverage) {
    // Silence is not evidence of completeness. An absent manifest tells us less than an empty
    // one, and must never read like "we looked and found nothing".
    return {
      state: 'unknown',
      missing: [],
      capturedSources: [],
      statement: (rowCount) =>
        `${rowCount === 0 ? 'No' : String(rowCount)} matching row${rowCount === 1 ? '' : 's'} — ` +
        'coverage UNKNOWN (no manifest). Absence here is not evidence of absence.',
      banner: () =>
        'Window — coverage UNKNOWN (no manifest)\n' +
        '  Nothing is known about which sources were captured for this window.',
    };
  }

  const missing: MissingSource[] = [
    ...coverage.elf.skipped
      .filter((s) => !SKIP_MEANS_PRESENT.has(s.reason))
      .map((s) => ({ source: s.type, reason: s.reason })),
    ...coverage.elf.failed.map((f) => ({ source: f.type, reason: f.reason })),
    ...coverage.rte.unavailable.map((u) => ({ source: u.object, reason: u.reason })),
    // A query that could not run is coverage loss under another name — the type was requested
    // and produced nothing, and the reason it produced nothing is not "there was nothing".
    ...coverage.accessErrors.map((e) => ({ source: e.scope, reason: e.reason })),
  ];

  const capturedSources = [
    ...new Set([
      ...coverage.elf.captured.map((c) => c.type),
      ...coverage.elf.skipped.filter((s) => SKIP_MEANS_PRESENT.has(s.reason)).map((s) => s.type),
      ...coverage.rte.captured.map((c) => c.object),
    ]),
  ].sort();

  const state: CoverageState = missing.length === 0 ? 'complete' : 'incomplete';

  return {
    state,
    missing,
    capturedSources,

    statement(rowCount) {
      const n = missing.length;
      if (state === 'complete') {
        return rowCount === 0
          ? 'No activity from this seed. Coverage complete.'
          : `${rowCount} matching row${rowCount === 1 ? '' : 's'}. Coverage complete.`;
      }
      const qualifier = `Coverage incomplete — ${n} source${n === 1 ? '' : 's'} missing.`;
      return rowCount === 0
        ? `No activity in captured sources. ${qualifier}`
        : `${rowCount} matching row${rowCount === 1 ? '' : 's'} in captured sources. ${qualifier}`;
    },

    banner() {
      const lines = [`Window — coverage ${state.toUpperCase()}`];
      if (capturedSources.length > 0) {
        lines.push(`  captured   ${capturedSources.join(', ')}`);
      }
      for (const m of missing) {
        lines.push(`  MISSING    ${m.source} (${m.reason})`);
      }
      return lines.join('\n');
    },
  };
}
