import { describe, it, expect } from '@jest/globals';
import * as path from 'node:path';
import { loadCaptures } from '../../../src/timeline/loadCaptures.js';
import { assessCoverage } from '../../../src/timeline/CaptureIndex.js';
import { correlate } from '../../../src/timeline/CorrelationEngine.js';
import { normaliseRow } from '../../../src/timeline/normalise.js';
import { renderCsv } from '../../../src/timeline/render.js';
import { EVENT_ROW_COLUMNS, type EventSource } from '../../../src/timeline/EventRow.js';

/**
 * One assertion over the whole pipeline, against a capture from a real org.
 *
 * The targeted tests each pin one behaviour, and between them they miss a class of regression
 * entirely: anything that changes the *shape* of the output rather than a value in it. Column
 * order is the clearest case — every existing test compares the CSV header to the same constant
 * the header is built from, so reordering the schema moves both sides together and nothing
 * fails. Downstream consumers break; CI stays green.
 *
 * The fixture is a sanitised capture rather than something invented. Identifiers are
 * pseudonymised deterministically, so every join relationship, blank field and cardinality ratio
 * survives exactly while no original value does — the structure is real, which matters because
 * the properties under test are structural. It carries a request that spans seven event types,
 * ninety-one rows with a blank request id, and four types that have no client-address column at
 * all: the shapes that make correlation hard, none of which anyone would think to invent.
 *
 * When this fails, the fix is to understand the diff, not to re-record the expectation. A golden
 * file that gets regenerated on every failure has stopped being a test.
 */
const CAPTURE = path.join(process.cwd(), 'test', 'fixtures', 'timeline', 'capture');
const ORG = '00Dxx0000000000EAA';

function runPipeline(seed: { type: 'clientIp' | 'requestId'; value: string }) {
  const loaded = loadCaptures({ base: CAPTURE, orgId: ORG, date: '2026-08-02', hours: ['04'] });
  const coverage = assessCoverage({ coverage: loaded.coverage });
  const result = correlate(loaded.rows, [seed], {});
  const rows = result.rows.map((c, i) =>
    normaliseRow(c.row, {
      seq: i + 1,
      attribution: c.attribution,
      source: (c.row.__source as EventSource) ?? 'EventLogFile',
    }),
  );
  return { loaded, coverage, result, rows };
}

describe('golden — the fixture loads as captured', () => {
  it('reads every row without losing any to a parse failure', () => {
    const { loaded } = runPipeline({ type: 'requestId', value: 'REQ000000' });

    expect(loaded.rows).toHaveLength(1156);
    expect(loaded.malformed).toBe(0);
    expect(loaded.unreadable).toBe(0);
    expect(loaded.windowPresent).toBe(true);
  });

  it('preserves the structural properties the fixture exists for', () => {
    const { loaded } = runPipeline({ type: 'requestId', value: 'REQ000000' });

    const blankRequestIds = loaded.rows.filter((r) => String(r.REQUEST_ID ?? '').trim() === '').length;
    const typesWithoutClientIp = [
      ...new Set(loaded.rows.filter((r) => !('CLIENT_IP' in r)).map((r) => String(r.EVENT_TYPE))),
    ].sort();

    // Real shapes, carried over verbatim. A fixture that tidied these away could not fail
    // against a naive implementation, which is the only reason to have one.
    expect(blankRequestIds).toBe(91);
    expect(typesWithoutClientIp).toEqual([
      'ApexUnexpectedException', 'DatabaseSave', 'FlowExecution', 'UniqueQuery',
    ]);
  });

  it('reports the coverage the manifest describes', () => {
    const { coverage } = runPipeline({ type: 'requestId', value: 'REQ000000' });

    expect(coverage.state).toBe('incomplete');
    expect(coverage.missing).toEqual([
      { source: 'LightningInteraction', reason: 'not-in-core-set' },
      { source: 'GuestUserAnomalyEventStore', reason: 'storage-disabled' },
    ]);
  });
});

describe('golden — correlating the seven-type cascade', () => {
  // The richest request in the capture: one action whose consequences land in seven event types,
  // three of which carry no client address and are reachable only through the request id.
  const SEED = { type: 'requestId' as const, value: 'REQ000000' };

  it('reaches the cascade and the actor activity around it', () => {
    const { rows } = runPipeline(SEED);
    const byType = new Map<string, number>();
    for (const r of rows) byType.set(r.event_type, (byType.get(r.event_type) ?? 0) + 1);

    // More than the seeded request, and correctly so. Nine rows carry the request id itself;
    // the rest are the same actor's surrounding activity, reached by expanding through their
    // user, address and session. That is the question the command answers — "what did this
    // actor do" — rather than "what was in this one request".
    expect(Object.fromEntries([...byType].sort())).toEqual({
      ApexCallout: 1,
      ApexExecution: 2,
      ApexUnexpectedException: 1,
      ApiTotalUsage: 2,
      DatabaseSave: 3,
      FlowExecution: 1,
      Logout: 1,
      NamedCredential: 1,
      QueuedExecution: 1,
      RestApi: 2,
    });
    expect(rows).toHaveLength(15);
  });

  it('records which rows the seed matched and which were reached by expanding', () => {
    const { rows } = runPipeline(SEED);
    const byAttribution = new Map<string, number>();
    for (const r of rows) byAttribution.set(String(r.attribution), (byAttribution.get(String(r.attribution)) ?? 0) + 1);

    // The split is the provenance: nine rows the operator asked for, six inferred. A reviewer
    // who distrusts the inference can discard those six and still have the seeded request.
    expect(Object.fromEntries([...byAttribution].sort())).toEqual({ seed: 9, userId: 6 });
  });

  it('walks the key types in a stable order', () => {
    const { result } = runPipeline(SEED);

    // Expansion order is provenance too — it shows which hop each conclusion rests on. Locked
    // here because a change to it means the search behaves differently, which is worth noticing
    // even when the row count happens to come out the same.
    expect(result.expandedThrough.map((e) => e.type)).toEqual([
      'requestId', 'userId', 'requestId', 'requestId', 'clientIp',
      'requestId', 'requestId', 'sessionKey', 'sessionKey',
    ]);
  });

  it('refuses nothing, because a request id identifies one actor', () => {
    const { result } = runPipeline(SEED);

    expect(result.refusals).toEqual([]);
  });
});

describe('golden — the rendered schema', () => {
  it('emits the columns in their declared order', () => {
    // The assertion the other tests cannot make: a literal header, not one derived from the
    // same constant the renderer uses. Reordering the schema fails here and only here.
    const { rows, coverage, result } = runPipeline({ type: 'requestId', value: 'REQ000000' });
    const csv = renderCsv({
      window: '2026-08-02T04:00Z/PT1H',
      seeds: [{ type: 'requestId', value: 'REQ000000' }],
      rows,
      refusals: result.refusals,
      expandedThrough: result.expandedThrough,
      coverage,
    });

    expect(csv.split('\n')[0]).toBe(
      'seq,timestamp_utc,event_type,source,attribution,' +
        'client_ip,request_id,session_key,login_key,user_id,user_type,is_guest,' +
        'transaction_id,event_identifier,related_event_identifier,' +
        'entity_name,record_ids,referrer_uri,user_agent,quiddity,' +
        'run_time_ms,response_bytes,page_name,http_method,is_error,uri,entry_point,' +
        'query_type,sql_id,' +
        'rows_processed,queried_entities,records_returned,list_view_name,list_view_scope,' +
        'filter_criteria,' +
        'graphql_operation,graphql_query,graphql_exception,' +
        'aura_action_summary,aura_action_message,source_file',
    );
  });

  it('declares exactly the columns it renders', () => {
    expect(EVENT_ROW_COLUMNS).toHaveLength(41);
  });

  it('writes one line per row and no more', () => {
    const { rows, coverage, result } = runPipeline({ type: 'requestId', value: 'REQ000000' });
    const csv = renderCsv({
      window: 'w', seeds: [], rows, refusals: result.refusals,
      expandedThrough: result.expandedThrough, coverage,
    });

    // A quoted newline anywhere in the data would break this, which is the point.
    expect(csv.split('\n')).toHaveLength(rows.length + 1);
  });
});
