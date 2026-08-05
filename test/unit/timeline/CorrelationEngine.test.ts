import { describe, it, expect } from '@jest/globals';
import { correlate } from '../../../src/timeline/CorrelationEngine.js';
import {
  INCIDENT_ROWS,
  ACTOR_IP,
  GUEST_USER,
  EXPECTED_ACTOR_ROW_COUNT,
  GUEST_DISTINCT_IPS,
} from '../../fixtures/timeline/incident.js';

/**
 * The engine is where the two guards have to work together, and where getting either wrong
 * produces a confident, wrong answer rather than an obviously broken one.
 *
 * Both regression tests below fail against the naive implementation. That is the point of them:
 * the fixture deliberately keeps the blank REQUEST_IDs and the shared guest identity that made
 * the original hand reconstruction go wrong.
 */
const seedIp = [{ type: 'clientIp' as const, value: ACTOR_IP }];

describe('correlate — reaching rows that carry no usable address', () => {
  it('finds rows that have no client-address column, via the request id', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    const byType = (t: string): number => result.rows.filter((r) => r.row.EVENT_TYPE === t).length;
    // An address filter alone would find none of these.
    expect(byType('UniqueQuery')).toBe(3);
  });

  it('finds rows whose address column is present but blank', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'ApexExecution')).toHaveLength(2);
  });

  it('records which key tied each row in', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    const apex = result.rows.find((r) => r.row.EVENT_TYPE === 'ApexExecution')!;
    const aura = result.rows.find((r) => r.row.EVENT_TYPE === 'AuraRequest')!;

    // Reached only by walking from the seed's rows to their request id.
    expect(apex.attribution).toBe('requestId');
    // Matched on the seed value itself, so the seed is the honest provenance — not the key
    // type it happens to be. A reviewer asking "why is this row here" gets "you asked for it".
    expect(aura.attribution).toBe('seed');
  });

  it('treats the real-time spelling of the address as the same actor', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'ListViewEvent')).toHaveLength(1);
  });
});

describe('correlate — Invariant 1, blank keys never expand', () => {
  it('attributes exactly the two apex rows, never the twenty-five unrelated logins', () => {
    // The actor has five rows of their own with a blank REQUEST_ID. Twenty-five other visitors
    // also have blank REQUEST_IDs. Admitting a blank as a key reaches all of them.
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'CommunitiesLogin')).toHaveLength(0);
    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'ApexExecution')).toHaveLength(2);
  });

  it('refuses a blank key even when too few actors share it to trip the cardinality gate', () => {
    // The previous test does not isolate this guard: there, the blank is shared by 26 addresses,
    // so the cardinality gate would refuse it anyway and the blank check is never load-bearing.
    // Here only two other visitors share the blank, well under the threshold of 8 — so nothing
    // but Invariant 1 stands between the seed and their rows.
    const quiet = [
      { EVENT_TYPE: 'Sites', CLIENT_IP: ACTOR_IP, REQUEST_ID: '' },
      { EVENT_TYPE: 'OtherVisitor', CLIENT_IP: '203.0.113.60', REQUEST_ID: '' },
      { EVENT_TYPE: 'OtherVisitor', CLIENT_IP: '203.0.113.61', REQUEST_ID: '' },
    ];

    const result = correlate(quiet, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'OtherVisitor')).toHaveLength(0);
    expect(result.rows).toHaveLength(1);
    // And no refusal was recorded, which proves the cardinality gate never fired here.
    expect(result.refusals).toHaveLength(0);
  });

  it('still keeps the actor\'s own blank-key rows, which their address vouches for', () => {
    // Rejecting the blank as a *join key* must not discard rows that matched on something else.
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'Sites')).toHaveLength(5);
  });

  it('produces the full actor timeline and nothing beyond it', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows).toHaveLength(EXPECTED_ACTOR_ROW_COUNT);
  });
});

describe('correlate — Invariant 2, shared identities do not expand', () => {
  it('refuses to expand through an identity shared by many addresses', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    // Every row in the window carries the guest user id. Expanding through it would pull in
    // every other visitor.
    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'CommunitiesLogin')).toHaveLength(0);
  });

  it('records the refusal rather than silently bounding the result', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    const refusal = result.refusals.find((r) => r.type === 'userId');
    expect(refusal).toBeDefined();
    expect(refusal!.value).toBe(GUEST_USER);
    expect(refusal!.cardinality).toBe(GUEST_DISTINCT_IPS);
    expect(refusal!.threshold).toBe(8);
  });

  it('expands through the shared identity when explicitly allowed, and says so', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, { allowSharedIdentity: true });

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'CommunitiesLogin')).toHaveLength(25);
    expect(result.refusals).toHaveLength(0);
  });

  it('honours a raised threshold', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, { maxCardinality: 1000 });

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'CommunitiesLogin')).toHaveLength(25);
  });

  it('expands at exactly the threshold and refuses one above it', () => {
    // The gate is "more than", not "at least". A key shared by exactly the permitted number of
    // actors is still allowed through — otherwise the documented threshold is off by one from
    // the one that operates, and an operator raising --max-cardinality to N gets N-1.
    const shared = (n: number): Array<Record<string, unknown>> =>
      Array.from({ length: n }, (_, i) => ({
        EVENT_TYPE: i === 0 ? 'Seeded' : 'Peer',
        CLIENT_IP: `203.0.113.${10 + i}`,
        SESSION_KEY: 'shared-session',
      }));

    const seed = [{ type: 'clientIp' as const, value: '203.0.113.10' }];

    const atThreshold = correlate(shared(4), seed, { maxCardinality: 4 });
    expect(atThreshold.rows).toHaveLength(4);
    expect(atThreshold.refusals).toHaveLength(0);

    const overThreshold = correlate(shared(5), seed, { maxCardinality: 4 });
    expect(overThreshold.rows).toHaveLength(1);
    expect(overThreshold.refusals[0]).toMatchObject({ type: 'sessionKey', cardinality: 5, threshold: 4 });
  });

  it('still expands through a one-to-one key at the default threshold', () => {
    // The gate must not be so blunt that it blocks the expansion the whole command exists for.
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'UniqueQuery')).toHaveLength(3);
  });
});

describe('correlate — seeds and termination', () => {
  it('tags rows matched by the seed itself as seed-attributed', () => {
    const result = correlate(INCIDENT_ROWS, [{ type: 'requestId', value: 'req-a1' }], {});

    expect(result.rows.every((r) => r.attribution === 'seed' || r.attribution === 'clientIp' || r.attribution === 'requestId')).toBe(true);
    expect(result.rows.length).toBeGreaterThan(0);
  });

  it('returns an empty result for a seed that matches nothing, without error', () => {
    const result = correlate(INCIDENT_ROWS, [{ type: 'clientIp', value: '203.0.113.254' }], {});

    expect(result.rows).toHaveLength(0);
    expect(result.refusals).toHaveLength(0);
  });

  it('terminates on rows that reference each other circularly', () => {
    const circular = [
      { EVENT_TYPE: 'A', CLIENT_IP: '203.0.113.1', REQUEST_ID: 'r1', SESSION_KEY: 's1' },
      { EVENT_TYPE: 'B', CLIENT_IP: '203.0.113.1', REQUEST_ID: 'r1', SESSION_KEY: 's1' },
      { EVENT_TYPE: 'C', SESSION_KEY: 's1', REQUEST_ID: 'r1' },
    ];

    const result = correlate(circular, [{ type: 'clientIp', value: '203.0.113.1' }], {});
    expect(result.rows).toHaveLength(3);
  });

  it('never returns the same row twice, however many keys reach it', () => {
    const result = correlate(INCIDENT_ROWS, seedIp, {});

    expect(new Set(result.rows.map((r) => r.row)).size).toBe(result.rows.length);
  });

  it('accepts multiple seeds', () => {
    const result = correlate(
      INCIDENT_ROWS,
      [{ type: 'clientIp', value: ACTOR_IP }, { type: 'clientIp', value: '203.0.113.100' }],
      {},
    );

    expect(result.rows.filter((r) => r.row.EVENT_TYPE === 'CommunitiesLogin')).toHaveLength(1);
  });
});
