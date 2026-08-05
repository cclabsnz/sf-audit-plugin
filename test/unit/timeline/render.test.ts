import { describe, it, expect } from '@jest/globals';
import { renderCsv, renderJson, renderSummary, type TimelineOutput } from '../../../src/timeline/render.js';
import { EVENT_ROW_COLUMNS, type EventRow } from '../../../src/timeline/EventRow.js';
import { assessCoverage } from '../../../src/timeline/CaptureIndex.js';

const row = (over: Partial<EventRow>): EventRow => {
  const base = {} as Record<string, unknown>;
  for (const c of EVENT_ROW_COLUMNS) base[c] = undefined;
  return Object.assign(base, {
    seq: 1,
    timestamp_utc: '2026-08-02T04:00:00.000Z',
    event_type: 'URI',
    source: 'EventLogFile',
    attribution: 'seed',
  }, over) as EventRow;
};

const completeCoverage = () =>
  assessCoverage({
    coverage: {
      orgId: '00Dxx0000000000EAA',
      capturedAt: '2026-08-02T05:00:00.000Z',
      interval: 'Hourly',
      elf: { requestedTypes: ['URI'], captured: [{ type: 'URI', id: '0AT1', logDate: '2026-08-02', hour: '04', bytes: 1, path: '/x' }], skipped: [], failed: [] },
      rte: { captured: [], unavailable: [] },
      accessErrors: [],
    },
  });

const incompleteCoverage = () =>
  assessCoverage({
    coverage: {
      orgId: '00Dxx0000000000EAA',
      capturedAt: '2026-08-02T05:00:00.000Z',
      interval: 'Hourly',
      elf: { requestedTypes: ['URI', 'UniqueQuery'], captured: [], skipped: [{ type: 'UniqueQuery', reason: 'no-permission' }], failed: [] },
      rte: { captured: [], unavailable: [] },
      accessErrors: [],
    },
  });

const output = (over: Partial<TimelineOutput> = {}): TimelineOutput => ({
  window: '2026-08-02T04:00Z/PT1H',
  seeds: [{ type: 'clientIp', value: '203.0.113.50' }],
  rows: [row({})],
  refusals: [],
  expandedThrough: [{ type: 'clientIp', value: '203.0.113.50' }],
  coverage: completeCoverage(),
  ...over,
});

describe('renderCsv', () => {
  it('writes the declared columns as the header, in order', () => {
    const [header] = renderCsv(output()).split('\n');

    expect(header).toBe(EVENT_ROW_COLUMNS.join(','));
  });

  it('escapes a value containing a comma', () => {
    const csv = renderCsv(output({ rows: [row({ uri: '/a,b' })] }));

    expect(csv).toContain('"/a,b"');
  });

  it('escapes embedded quotes by doubling them', () => {
    const csv = renderCsv(output({ rows: [row({ uri: 'say "hi"' })] }));

    expect(csv).toContain('"say ""hi"""');
  });

  it('terminates the final line, so line-counting tools agree with the row count', () => {
    // `wc -l` counts newlines. Without a trailing one it reports a row fewer than the file
    // holds, and a count taken that way from an evidence export is quietly wrong.
    const csv = renderCsv(output({ rows: [row({}), row({ seq: 2 })] }));

    expect(csv.endsWith('\n')).toBe(true);
    expect(csv.split('\n').filter((l) => l !== '')).toHaveLength(3); // header + 2 rows
  });

  it('escapes a value containing a newline, so one row stays one line', () => {
    const csv = renderCsv(output({ rows: [row({ graphql_query: 'query {\n  a\n}' })] }));
    const dataLines = csv.split('\n').slice(1);

    expect(csv).toContain('"query {');
    // The record spans lines only inside quotes; the unquoted line count must not grow.
    expect(dataLines.filter((l) => l.startsWith('1,')).length).toBe(1);
  });

  it('writes an empty cell for an absent value rather than the word undefined', () => {
    const csv = renderCsv(output({ rows: [row({ uri: undefined })] }));

    expect(csv).not.toContain('undefined');
  });

  it('keeps a zero, which is a finding rather than an absence', () => {
    const csv = renderCsv(output({ rows: [row({ rows_processed: 0 })] }));
    const cells = csv.split('\n')[1].split(',');

    expect(cells[EVENT_ROW_COLUMNS.indexOf('rows_processed')]).toBe('0');
  });

  it('orders rows chronologically regardless of input order', () => {
    // Real-time queries reject ORDER BY on the event date, so ordering is ours to do.
    const csv = renderCsv(output({
      rows: [
        row({ seq: 1, timestamp_utc: '2026-08-02T04:05:00.000Z', event_type: 'Late' }),
        row({ seq: 2, timestamp_utc: '2026-08-02T04:01:00.000Z', event_type: 'Early' }),
      ],
    }));
    const [, first, second] = csv.split('\n');

    expect(first).toContain('Early');
    expect(second).toContain('Late');
  });
});

describe('renderJson', () => {
  it('carries the rows and the provenance of how they were reached', () => {
    const parsed = JSON.parse(renderJson(output({
      refusals: [{ type: 'userId', value: 'guest', cardinality: 1371, threshold: 8 }],
    })));

    expect(parsed.rows).toHaveLength(1);
    expect(parsed.seeds).toEqual([{ type: 'clientIp', value: '203.0.113.50' }]);
    expect(parsed.expandedThrough).toHaveLength(1);
    expect(parsed.refusals[0]).toMatchObject({ type: 'userId', cardinality: 1371, threshold: 8 });
  });

  it('states coverage in the machine-readable output too', () => {
    const parsed = JSON.parse(renderJson(output({ coverage: incompleteCoverage() })));

    expect(parsed.coverage.state).toBe('incomplete');
    expect(parsed.coverage.missing).toEqual([{ source: 'UniqueQuery', reason: 'no-permission' }]);
    expect(parsed.coverage.statement).toContain('Coverage incomplete');
  });

  it('is valid JSON even with values that need escaping', () => {
    const json = renderJson(output({ rows: [row({ graphql_query: 'a "b" \n c' })] }));

    expect(() => JSON.parse(json)).not.toThrow();
  });
});

describe('renderSummary', () => {
  it('leads with the coverage banner before any finding', () => {
    const md = renderSummary(output({ coverage: incompleteCoverage() }));
    const bannerAt = md.indexOf('coverage INCOMPLETE');
    const countsAt = md.indexOf('Rows by event type');

    expect(bannerAt).toBeGreaterThan(-1);
    expect(bannerAt).toBeLessThan(countsAt);
  });

  it('qualifies an empty result with the coverage statement', () => {
    const md = renderSummary(output({ rows: [], coverage: incompleteCoverage() }));

    expect(md).toContain('No activity in captured sources');
    expect(md).toContain('1 source missing');
  });

  it('does not qualify an empty result when coverage is complete', () => {
    const md = renderSummary(output({ rows: [], coverage: completeCoverage() }));

    expect(md).toContain('No activity from this seed. Coverage complete.');
  });

  it('counts rows per event type', () => {
    const md = renderSummary(output({
      rows: [row({ event_type: 'URI' }), row({ event_type: 'URI' }), row({ event_type: 'UniqueQuery' })],
    }));

    expect(md).toMatch(/URI\s*\|\s*2/);
    expect(md).toMatch(/UniqueQuery\s*\|\s*1/);
  });

  it('breaks rows down by what tied them in', () => {
    const md = renderSummary(output({
      rows: [row({ attribution: 'seed' }), row({ attribution: 'requestId' }), row({ attribution: 'requestId' })],
    }));

    expect(md).toMatch(/requestId\s*\|\s*2/);
  });

  it('states every expansion it refused, with the evidence', () => {
    const md = renderSummary(output({
      refusals: [{ type: 'userId', value: '005xx0guest', cardinality: 1371, threshold: 8 }],
    }));

    expect(md).toContain('005xx0guest');
    expect(md).toContain('1371');
    expect(md).toContain('threshold 8');
    expect(md).toContain('--allow-shared-identity');
  });

  it('says plainly when nothing was refused', () => {
    // Silence about refusals is ambiguous; an investigator needs to know none happened.
    expect(renderSummary(output())).toContain('No expansions were refused');
  });

  it('states the did-records-leave finding when a real-time row supplied one', () => {
    const md = renderSummary(output({
      rows: [row({ event_type: 'ListViewEvent', source: 'RealTimeEventMonitoring', rows_processed: 0, records_returned: '[]' })],
    }));

    expect(md).toContain('Records returned');
    expect(md).toContain('0');
  });

  it('says the question is unanswerable when no real-time row was captured', () => {
    // Every EventLogFile type leaves these blank. The distinction being drawn is between "we
    // know nothing left" and "we cannot tell" — so the section has to say it is unanswerable
    // outright. Naming only the missing source would still read as an absence of records.
    const md = renderSummary(output({ rows: [row({ source: 'EventLogFile' })] }));

    expect(md).toContain('## Did records leave');
    expect(md).toContain('Unanswerable from this capture');
    expect(md).toContain('no EventLogFile type records how many records a query returned');
  });

  it('renders its sections in the order a reader needs them', () => {
    // Caveats before findings. A reader who has absorbed a row count does not revise that
    // impression when the qualification arrives afterwards.
    const md = renderSummary(output({ coverage: incompleteCoverage() }));
    const order = ['## Coverage', '## Rows by event type', '## Rows by attribution', '## Expansions refused', '## Did records leave']
      .map((heading) => md.indexOf(heading));

    expect(order.every((i) => i > -1)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });
});
