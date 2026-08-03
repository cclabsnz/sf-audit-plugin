import { describe, it, expect } from '@jest/globals';
import { buildCardinalityIndex } from '../../../src/timeline/CardinalityIndex.js';

/**
 * Invariant 2 — a shared identity does not expand.
 *
 * Some join keys identify one actor and some identify a crowd. REQUEST_ID is 1:1 and expanding
 * through it is exactly right. A community guest USER_ID is not: during the 2026-08-02 hour a
 * single guest user was shared by 1,371 distinct client IPs, and expanding through it would turn
 * a 177-row timeline into every anonymous visitor's activity — 34,721 rows, presented as one
 * actor's.
 *
 * Cardinality is measured in distinct *client IPs* rather than distinct rows, because rows say
 * how busy a key was and IPs say how many actors stand behind it. A single actor making 10,000
 * requests must stay expandable; ten actors sharing one key must not.
 *
 * The index answers only "how many actors share this value". The decision to refuse belongs to
 * the engine, which records the reason — a silently bounded timeline is as dishonest as an
 * over-attributed one.
 */
const row = (clientIp: string | undefined, keys: Record<string, string>): Record<string, unknown> => ({
  ...(clientIp === undefined ? {} : { CLIENT_IP: clientIp }),
  ...keys,
});

describe('buildCardinalityIndex', () => {
  it('reports one actor for a key used by a single IP', () => {
    const index = buildCardinalityIndex([
      row('203.0.113.10', { REQUEST_ID: 'req-1' }),
      row('203.0.113.10', { REQUEST_ID: 'req-1' }),
    ]);

    expect(index.cardinality('requestId', 'req-1')).toBe(1);
  });

  it('counts distinct actors, not rows', () => {
    // Ten rows, one IP: still one actor. Volume must not look like sharing.
    const rows = Array.from({ length: 10 }, () => row('203.0.113.10', { SESSION_KEY: 'sess-1' }));

    expect(index_of(rows).cardinality('sessionKey', 'sess-1')).toBe(1);
  });

  it('counts every distinct IP behind a shared key', () => {
    const rows = Array.from({ length: 50 }, (_, i) =>
      row(`203.0.113.${i}`, { USER_ID: 'guest' }),
    );

    expect(index_of(rows).cardinality('userId', 'guest')).toBe(50);
  });

  it('separates values of the same key type', () => {
    const index = index_of([
      row('203.0.113.10', { USER_ID: 'alice' }),
      row('203.0.113.11', { USER_ID: 'guest' }),
      row('203.0.113.12', { USER_ID: 'guest' }),
    ]);

    expect(index.cardinality('userId', 'alice')).toBe(1);
    expect(index.cardinality('userId', 'guest')).toBe(2);
  });

  it('does not conflate the same value appearing under different key types', () => {
    // A session key and a login key could coincidentally hold the same string; they are
    // different identities and must be counted apart.
    const index = index_of([
      row('203.0.113.10', { SESSION_KEY: 'shared', LOGIN_KEY: 'shared' }),
      row('203.0.113.11', { LOGIN_KEY: 'shared' }),
    ]);

    expect(index.cardinality('sessionKey', 'shared')).toBe(1);
    expect(index.cardinality('loginKey', 'shared')).toBe(2);
  });

  it('ignores blank keys, consistently with JoinKeys', () => {
    // A blank never becomes a key, so it can never accumulate a cardinality either.
    const index = index_of([
      row('203.0.113.10', { REQUEST_ID: '' }),
      row('203.0.113.11', { REQUEST_ID: '   ' }),
    ]);

    expect(index.cardinality('requestId', '')).toBe(0);
  });

  it('reports zero for a value it never saw', () => {
    expect(index_of([row('203.0.113.10', { REQUEST_ID: 'req-1' })]).cardinality('requestId', 'nope')).toBe(0);
  });

  it('still counts a key on rows that carry no client IP at all', () => {
    // UniqueQuery has no CLIENT_IP column. Such a row cannot contribute a distinct actor, but
    // it must not crash the index or make the key look unseen — the key exists, with no actor
    // evidence attached to it yet.
    const index = index_of([
      row(undefined, { REQUEST_ID: 'req-1' }),
      row('203.0.113.10', { REQUEST_ID: 'req-1' }),
    ]);

    expect(index.cardinality('requestId', 'req-1')).toBe(1);
  });

  it('treats a real-time SourceIp as the actor address', () => {
    const index = buildCardinalityIndex([
      { SourceIp: '203.0.113.10', USER_ID: 'guest' },
      { SourceIp: '203.0.113.11', USER_ID: 'guest' },
    ]);

    expect(index.cardinality('userId', 'guest')).toBe(2);
  });

  it('scales to the shape that motivated the gate', () => {
    // 1,371 distinct IPs behind one guest user, the measured ratio from the incident.
    const rows = Array.from({ length: 1371 }, (_, i) =>
      row(`203.0.113.${i % 254}.${Math.floor(i / 254)}`, { USER_ID: 'guest', REQUEST_ID: `req-${i}` }),
    );
    const index = index_of(rows);

    expect(index.cardinality('userId', 'guest')).toBeGreaterThan(8);
    expect(index.cardinality('requestId', 'req-7')).toBe(1);
  });
});

function index_of(rows: Array<Record<string, unknown>>) {
  return buildCardinalityIndex(rows);
}
