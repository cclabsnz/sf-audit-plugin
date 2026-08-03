import { describe, it, expect } from '@jest/globals';
import { joinKeysOf, type JoinKeys } from '../../../src/timeline/JoinKeys.js';

/**
 * Invariant 1 — a blank key never joins.
 *
 * Correlating an actor across event types means expanding through shared values: this row's
 * REQUEST_ID finds those rows, whose SESSION_KEY finds others. If a blank value is allowed into
 * that set, it stops being an identifier and becomes a match-all: every row whose REQUEST_ID is
 * also blank gets attributed to the actor.
 *
 * This is not hypothetical. Reconstructing the 2026-08-02 sweep by hand, 5 of 32 Sites rows had
 * a blank REQUEST_ID, and building the join set without filtering them pulled in 25 unrelated
 * login rows from other visitors. The true count was 2.
 *
 * The guard lives here rather than in the correlation engine deliberately. A blank cannot reach
 * the frontier if it never becomes a key in the first place, so the engine has no opportunity to
 * get this wrong and no need to remember to check.
 */
const raw = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  REQUEST_ID: 'req-1',
  CLIENT_IP: '203.0.113.10',
  SESSION_KEY: 'sess-1',
  LOGIN_KEY: 'login-1',
  USER_ID: '005xx000000000',
  ...over,
});

describe('joinKeysOf', () => {
  it('extracts every join key from a fully populated row', () => {
    expect(joinKeysOf(raw())).toEqual<JoinKeys>({
      requestId: 'req-1',
      clientIp: '203.0.113.10',
      sessionKey: 'sess-1',
      loginKey: 'login-1',
      userId: '005xx000000000',
    });
  });

  it.each([
    ['empty string', ''],
    ['spaces', '   '],
    ['tab', '\t'],
    ['null', null],
    ['undefined', undefined],
    ['missing entirely', Symbol('absent')],
  ])('returns undefined for a %s REQUEST_ID rather than a usable key', (_label, value) => {
    const row = raw();
    if (typeof value === 'symbol') delete row.REQUEST_ID;
    else row.REQUEST_ID = value;

    expect(joinKeysOf(row).requestId).toBeUndefined();
  });

  it('applies the same rule to every key, not just REQUEST_ID', () => {
    const blanked = joinKeysOf(
      raw({ REQUEST_ID: '', CLIENT_IP: '  ', SESSION_KEY: null, LOGIN_KEY: undefined, USER_ID: '\t' }),
    );

    expect(blanked).toEqual<JoinKeys>({
      requestId: undefined,
      clientIp: undefined,
      sessionKey: undefined,
      loginKey: undefined,
      userId: undefined,
    });
  });

  it('does not confuse a blank key with an absent one — both are unusable', () => {
    expect(joinKeysOf({})).toEqual(joinKeysOf(raw({
      REQUEST_ID: '', CLIENT_IP: '', SESSION_KEY: '', LOGIN_KEY: '', USER_ID: '',
    })));
  });

  it('trims a key that has usable content, so padding does not fork the identity', () => {
    // ' req-1 ' and 'req-1' are the same request; treating them as two keys would split an
    // actor's rows across two frontier values and under-report.
    expect(joinKeysOf(raw({ REQUEST_ID: ' req-1 ' })).requestId).toBe('req-1');
  });

  it('keeps a short identifier that looks like a zero', () => {
    // '0' is a legitimate identifier and survives here — the string is truthy, so a truthiness
    // check would keep it too. It is asserted because the guard is about emptiness, and the
    // obvious way to get emptiness wrong is to reach for a numeric or falsy test instead.
    expect(joinKeysOf(raw({ USER_ID: '0' })).userId).toBe('0');
  });

  it('accepts the real-time event spelling of a client address', () => {
    // RTE objects carry SourceIp where ELF carries CLIENT_IP; both mean the same actor.
    expect(joinKeysOf({ SourceIp: '203.0.113.11' }).clientIp).toBe('203.0.113.11');
  });

  it('prefers an explicit CLIENT_IP over SourceIp when a row somehow carries both', () => {
    expect(joinKeysOf({ CLIENT_IP: '203.0.113.10', SourceIp: '203.0.113.11' }).clientIp).toBe('203.0.113.10');
  });

  it('ignores a blank CLIENT_IP and falls through to SourceIp', () => {
    // ApexExecution carries CLIENT_IP as a column but leaves it empty in practice. A row that
    // has a usable SourceIp must not be stranded by the empty column that outranks it.
    expect(joinKeysOf({ CLIENT_IP: '', SourceIp: '203.0.113.11' }).clientIp).toBe('203.0.113.11');
  });
});
