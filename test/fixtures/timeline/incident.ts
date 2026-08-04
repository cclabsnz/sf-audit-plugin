/**
 * Sanitised extract of the 2026-08-02 recon sweep, shaped to preserve the properties under test.
 *
 * Addresses are TEST-NET-3 (203.0.113.0/24) and identifiers are fixture-shaped. What is kept
 * verbatim is the structure that made the incident hard to reconstruct correctly:
 *
 *   - one event type carries no client-address column, reachable only by REQUEST_ID
 *   - one carries the column but leaves it blank, also reachable only by REQUEST_ID
 *   - some of the actor's own rows have a blank REQUEST_ID
 *   - unrelated visitors' rows *also* have a blank REQUEST_ID, so a blank used as a key
 *     matches them
 *   - the guest identity is shared far more widely than any real actor
 *
 * A fixture that tidied any of these away would pass against the naive implementation, which
 * would make the regression tests decorative.
 */

export const ACTOR_IP = '203.0.113.50';
export const GUEST_USER = '005xx000000guest';

type Row = Record<string, unknown>;

const actorRequests = ['req-a1', 'req-a2', 'req-a3'];

/** Rows the actor produced that carry their address directly. */
const addressed: Row[] = [
  ...actorRequests.map((id, i) => ({
    EVENT_TYPE: 'AuraRequest',
    TIMESTAMP_DERIVED: `2026-08-02T04:0${i}:00.000Z`,
    CLIENT_IP: ACTOR_IP,
    REQUEST_ID: id,
    USER_ID: GUEST_USER,
  })),
  {
    EVENT_TYPE: 'URI',
    TIMESTAMP_DERIVED: '2026-08-02T04:03:00.000Z',
    CLIENT_IP: ACTOR_IP,
    REQUEST_ID: 'req-a1',
    USER_ID: GUEST_USER,
  },
];

/**
 * The actor's own rows with a blank REQUEST_ID. These are the bait: they are legitimately the
 * actor's (their address matches), but the key they carry is unusable.
 */
const actorBlankRequestId: Row[] = Array.from({ length: 5 }, (_, i) => ({
  EVENT_TYPE: 'Sites',
  TIMESTAMP_DERIVED: `2026-08-02T04:1${i}:00.000Z`,
  CLIENT_IP: ACTOR_IP,
  REQUEST_ID: '',
  USER_ID: GUEST_USER,
}));

/** No client-address column at all. Reachable only by expanding through REQUEST_ID. */
const noAddressColumn: Row[] = actorRequests.map((id, i) => ({
  EVENT_TYPE: 'UniqueQuery',
  TIMESTAMP_DERIVED: `2026-08-02T04:0${i}:30.000Z`,
  REQUEST_ID: id,
  USER_ID: GUEST_USER,
}));

/** Column present, value blank — the second type reachable only by REQUEST_ID. */
const blankAddressColumn: Row[] = [
  { EVENT_TYPE: 'ApexExecution', TIMESTAMP_DERIVED: '2026-08-02T04:00:45.000Z', CLIENT_IP: '', REQUEST_ID: 'req-a1', USER_ID: GUEST_USER },
  { EVENT_TYPE: 'ApexExecution', TIMESTAMP_DERIVED: '2026-08-02T04:01:45.000Z', CLIENT_IP: '', REQUEST_ID: 'req-a2', USER_ID: GUEST_USER },
];

/**
 * Other visitors, each with their own address, all sharing the guest identity — and all with a
 * blank REQUEST_ID. If a blank is ever treated as a key, seeding on the actor reaches every one
 * of these.
 */
const otherVisitors: Row[] = Array.from({ length: 25 }, (_, i) => ({
  EVENT_TYPE: 'CommunitiesLogin',
  TIMESTAMP_DERIVED: `2026-08-02T04:2${i % 10}:00.000Z`,
  CLIENT_IP: `203.0.113.${100 + i}`,
  REQUEST_ID: '',
  USER_ID: GUEST_USER,
}));

/** Real-time rows, which spell the address differently and carry the did-records-leave fields. */
const realtime: Row[] = [
  {
    EVENT_TYPE: 'ListViewEvent',
    TIMESTAMP_DERIVED: '2026-08-02T04:05:00.000Z',
    SourceIp: ACTOR_IP,
    RowsProcessed: 0,
    USER_ID: GUEST_USER,
  },
];

/** The whole captured window, in no particular order — ordering is the renderer's job. */
export const INCIDENT_ROWS: Row[] = [
  ...addressed,
  ...actorBlankRequestId,
  ...noAddressColumn,
  ...blankAddressColumn,
  ...otherVisitors,
  ...realtime,
];

/**
 * Everything genuinely attributable to the actor: rows carrying their address, plus rows
 * reachable from those rows' usable REQUEST_IDs.
 */
export const EXPECTED_ACTOR_ROW_COUNT =
  addressed.length + actorBlankRequestId.length + noAddressColumn.length + blankAddressColumn.length + realtime.length;

/** How many distinct addresses stand behind the shared guest identity in this window. */
export const GUEST_DISTINCT_IPS = 1 + otherVisitors.length;
