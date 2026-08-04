import { describe, it, expect } from '@jest/globals';
import { assessCoverage, type CoverageInput } from '../../../src/timeline/CaptureIndex.js';

/**
 * §4.5 — the ambiguity guard.
 *
 * A forensic tool that reports an absence without qualifying its coverage produces false
 * assurance, which is worse than reporting nothing. "No rows matched" means one of two entirely
 * different things: the actor did nothing, or nobody captured the hour they did it in. The
 * reader cannot tell those apart from a row count, so the tool must not make them guess.
 *
 * The wording is therefore driven by state rather than composed by the caller. These tests pin
 * the three states to their statements, because the failure mode here is a sentence that reads
 * as reassurance when the evidence does not support one.
 */
const coverage = (over: Partial<CoverageInput['coverage']> = {}): CoverageInput['coverage'] => ({
  orgId: '00Dxx0000000000EAA',
  capturedAt: '2026-08-02T05:00:00.000Z',
  interval: 'Hourly',
  elf: { requestedTypes: ['AuraRequest', 'UniqueQuery'], captured: [], skipped: [], failed: [] },
  rte: { captured: [], unavailable: [] },
  accessErrors: [],
  ...over,
});

const captured = (type: string) => ({ type, id: `0AT${type}`, logDate: '2026-08-02', hour: '04', bytes: 10, path: `/x/${type}` });

describe('assessCoverage — state', () => {
  it('is complete when every requested source was captured', () => {
    const result = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest', 'UniqueQuery'],
          captured: [captured('AuraRequest'), captured('UniqueQuery')],
          skipped: [],
          failed: [],
        },
      }),
    });

    expect(result.state).toBe('complete');
    expect(result.missing).toHaveLength(0);
  });

  it('is incomplete when a requested type was skipped', () => {
    const result = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest', 'UniqueQuery'],
          captured: [captured('AuraRequest')],
          skipped: [{ type: 'UniqueQuery', reason: 'not-in-core-set' }],
          failed: [],
        },
      }),
    });

    expect(result.state).toBe('incomplete');
    expect(result.missing).toEqual([{ source: 'UniqueQuery', reason: 'not-in-core-set' }]);
  });

  it('treats a failed download as missing, not as captured', () => {
    const result = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest'],
          captured: [],
          skipped: [],
          failed: [{ type: 'AuraRequest', reason: 'download-failed' }],
        },
      }),
    });

    expect(result.state).toBe('incomplete');
    expect(result.missing).toEqual([{ source: 'AuraRequest', reason: 'download-failed' }]);
  });

  it('counts an unavailable real-time object as missing coverage', () => {
    const result = assessCoverage({
      coverage: coverage({
        elf: { requestedTypes: [], captured: [], skipped: [], failed: [] },
        rte: {
          captured: [{ object: 'ListViewEvent', rows: 3, via: 'base', paths: ['/x'] }],
          unavailable: [{ object: 'GuestUserAnomalyEventStore', reason: 'storage-disabled' }],
        },
      }),
    });

    expect(result.state).toBe('incomplete');
    expect(result.missing).toEqual([{ source: 'GuestUserAnomalyEventStore', reason: 'storage-disabled' }]);
  });

  it('is unknown when there is no manifest at all', () => {
    // Never assume completeness from silence. An absent manifest is less information than an
    // empty one, and must not read the same as "we looked and found nothing".
    const result = assessCoverage({ coverage: undefined });

    expect(result.state).toBe('unknown');
  });

  it('reports an already-captured skip as covered, not missing', () => {
    // Dedup on a re-run means the data is on disk from an earlier pull. That is coverage.
    const result = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest'],
          captured: [],
          skipped: [{ type: 'AuraRequest', reason: 'already-captured' }],
          failed: [],
        },
      }),
    });

    expect(result.state).toBe('complete');
    expect(result.missing).toHaveLength(0);
  });
});

describe('assessCoverage — the statement that qualifies a row count', () => {
  const complete = () =>
    assessCoverage({
      coverage: coverage({
        elf: { requestedTypes: ['AuraRequest'], captured: [captured('AuraRequest')], skipped: [], failed: [] },
      }),
    });

  const incomplete = () =>
    assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest', 'UniqueQuery'],
          captured: [captured('AuraRequest')],
          skipped: [{ type: 'UniqueQuery', reason: 'no-permission' }],
          failed: [],
        },
      }),
    });

  it('calls a complete, empty result a real absence', () => {
    expect(complete().statement(0)).toBe('No activity from this seed. Coverage complete.');
  });

  it('qualifies an empty result when sources are missing', () => {
    expect(incomplete().statement(0)).toBe(
      'No activity in captured sources. Coverage incomplete — 1 source missing.',
    );
  });

  it('pluralises the missing-source count', () => {
    const two = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['A', 'B', 'C'],
          captured: [captured('A')],
          skipped: [{ type: 'B', reason: 'unlicensed' }, { type: 'C', reason: 'too-large' }],
          failed: [],
        },
      }),
    });

    expect(two.statement(0)).toContain('2 sources missing');
  });

  it('never claims completeness without a manifest', () => {
    const statement = assessCoverage({ coverage: undefined }).statement(0);

    expect(statement).toContain('coverage UNKNOWN');
    expect(statement).not.toContain('Coverage complete');
  });

  it('still qualifies a non-empty result when coverage is incomplete', () => {
    // Rows were found, but the reader must know they are not the whole picture.
    expect(incomplete().statement(42)).toContain('Coverage incomplete');
    expect(incomplete().statement(42)).toContain('42');
  });

  it('does not qualify a non-empty result when coverage is complete', () => {
    expect(complete().statement(42)).toBe('42 matching rows. Coverage complete.');
  });
});

describe('assessCoverage — banner', () => {
  it('names each missing source with the reason it is missing', () => {
    const result = assessCoverage({
      coverage: coverage({
        elf: {
          requestedTypes: ['AuraRequest', 'LightningInteraction'],
          captured: [captured('AuraRequest')],
          skipped: [{ type: 'LightningInteraction', reason: 'not-in-core-set' }],
          failed: [],
        },
        rte: {
          captured: [{ object: 'ListViewEvent', rows: 3, via: 'base', paths: ['/x'] }],
          unavailable: [{ object: 'GuestUserAnomalyEventStore', reason: 'storage-disabled' }],
        },
      }),
    });

    const banner = result.banner();
    expect(banner).toContain('coverage INCOMPLETE');
    expect(banner).toContain('LightningInteraction');
    expect(banner).toContain('not-in-core-set');
    expect(banner).toContain('GuestUserAnomalyEventStore');
    expect(banner).toContain('storage-disabled');
    // What *was* captured matters too — a reader needs to know the search had something to search.
    expect(banner).toContain('AuraRequest');
    expect(banner).toContain('ListViewEvent');
  });

  it('surfaces a query-level access error, which is coverage loss by another name', () => {
    const result = assessCoverage({
      coverage: coverage({ accessErrors: [{ scope: 'EventLogFile', reason: 'no-permission' }] }),
    });

    expect(result.state).toBe('incomplete');
    expect(result.banner()).toContain('EventLogFile');
    expect(result.banner()).toContain('no-permission');
  });
});
