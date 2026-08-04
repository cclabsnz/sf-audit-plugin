import { describe, it, expect } from '@jest/globals';
import { normaliseRow, collapseAuraActions } from '../../../src/timeline/normalise.js';
import { EVENT_ROW_COLUMNS } from '../../../src/timeline/EventRow.js';

/**
 * Mapping every source type into one shape.
 *
 * The mapping is table-driven rather than a branch per type, because there are more than sixty
 * event types and the ones this tool has never seen still have to survive. An unknown type must
 * map its common fields and leave the rest blank rather than being dropped — Salesforce adds
 * types, and a forensic tool that silently ignores the new one is worse than one that shows it
 * partially.
 */
describe('normaliseRow — common fields', () => {
  it('maps an EventLogFile row into the unified shape', () => {
    const row = normaliseRow(
      {
        EVENT_TYPE: 'AuraRequest',
        TIMESTAMP_DERIVED: '2026-08-02T04:00:00.000Z',
        CLIENT_IP: '203.0.113.50',
        REQUEST_ID: 'req-1',
        USER_ID: '005xx1',
        USER_TYPE: 'Guest',
        RUN_TIME: '412',
      },
      { seq: 1, attribution: 'seed', source: 'EventLogFile' },
    );

    expect(row).toMatchObject({
      seq: 1,
      event_type: 'AuraRequest',
      source: 'EventLogFile',
      attribution: 'seed',
      client_ip: '203.0.113.50',
      request_id: 'req-1',
      user_id: '005xx1',
      user_type: 'Guest',
      run_time_ms: 412,
    });
  });

  it('marks a guest actor, which is the difference between one visitor and anyone', () => {
    const guest = normaliseRow({ USER_TYPE: 'Guest' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });
    const named = normaliseRow({ USER_TYPE: 'Standard' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });

    expect(guest.is_guest).toBe(true);
    expect(named.is_guest).toBe(false);
  });

  it('carries the causal keys through to the output', () => {
    const row = normaliseRow(
      {
        TRANSACTION_ID: 'txn-1',
        EventIdentifier: 'evt-2',
        RelatedEventIdentifier: 'evt-1',
        ENTITY_NAME: 'Contact',
        REFERRER_URI: '/s/search',
        USER_AGENT: 'Mozilla/5.0',
        QUIDDITY: 'AURA',
      },
      { seq: 1, attribution: 'transactionId', source: 'EventLogFile' },
    );

    expect(row).toMatchObject({
      transaction_id: 'txn-1',
      event_identifier: 'evt-2',
      related_event_identifier: 'evt-1',
      entity_name: 'Contact',
      referrer_uri: '/s/search',
      user_agent: 'Mozilla/5.0',
      quiddity: 'AURA',
    });
  });

  it('reads the real-time spellings of the shared fields', () => {
    const row = normaliseRow(
      { EventDate: '2026-08-02T04:05:00Z', SourceIp: '203.0.113.50', SessionKey: 's1', UserId: '005xx1' },
      { seq: 2, attribution: 'clientIp', source: 'RealTimeEventMonitoring' },
    );

    expect(row).toMatchObject({
      timestamp_utc: '2026-08-02T04:05:00Z',
      client_ip: '203.0.113.50',
      session_key: 's1',
      user_id: '005xx1',
    });
  });

  it('keeps the did-records-leave fields as first-class columns', () => {
    const row = normaliseRow(
      { RowsProcessed: 0, QueriedEntities: 'Contact', RecordIds: '[]', Name: 'All Contacts', Scope: 'Everything' },
      { seq: 3, attribution: 'clientIp', source: 'RealTimeEventMonitoring' },
    );

    // Zero is the answer that matters most here, and it must not be dropped for being falsy.
    expect(row.rows_processed).toBe(0);
    expect(row.queried_entities).toBe('Contact');
    expect(row.records_returned).toBe('[]');
    expect(row.list_view_name).toBe('All Contacts');
  });

  it('leaves the record-count fields empty for EventLogFile rows', () => {
    // No ELF type records them. The blank is informative: it is why real-time capture matters.
    const row = normaliseRow({ EVENT_TYPE: 'URI' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });

    expect(row.rows_processed).toBeUndefined();
    expect(row.records_returned).toBeUndefined();
  });

  it('maps an unknown event type without losing its common fields', () => {
    const row = normaliseRow(
      { EVENT_TYPE: 'SomeTypeSalesforceAddedLastWeek', CLIENT_IP: '203.0.113.50', REQUEST_ID: 'req-9' },
      { seq: 4, attribution: 'seed', source: 'EventLogFile' },
    );

    expect(row.event_type).toBe('SomeTypeSalesforceAddedLastWeek');
    expect(row.client_ip).toBe('203.0.113.50');
    expect(row.request_id).toBe('req-9');
  });

  it('treats a blank field as absent rather than as an empty string', () => {
    const row = normaliseRow({ CLIENT_IP: '   ', REQUEST_ID: '' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });

    expect(row.client_ip).toBeUndefined();
    expect(row.request_id).toBeUndefined();
  });

  it('falls through a blank alias to a later one that has content', () => {
    // ENTITY_NAME is blank but EntityName has the value. Returning the first *string* rather
    // than the first usable one would yield an empty column and lose the field entirely.
    const row = normaliseRow(
      { ENTITY_NAME: '   ', EntityName: 'Contact' },
      { seq: 1, attribution: 'seed', source: 'EventLogFile' },
    );

    expect(row.entity_name).toBe('Contact');
  });

  it('does not let a generically-named ELF column leak into a real-time field', () => {
    // `Name` and `RowsProcessed` are how real-time objects spell a list view and its result
    // count. An EventLogFile row that happens to carry either must not be read as though it
    // answered "did records leave" — that column existing at all is the finding.
    const row = normaliseRow(
      { EVENT_TYPE: 'URI', Name: 'not a list view', RowsProcessed: 999, Scope: 'nope' },
      { seq: 1, attribution: 'seed', source: 'EventLogFile' },
    );

    expect(row.list_view_name).toBeUndefined();
    expect(row.rows_processed).toBeUndefined();
    expect(row.list_view_scope).toBeUndefined();
  });

  it('does not invent a numeric value from an unparseable one', () => {
    const row = normaliseRow({ RUN_TIME: 'n/a' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });

    expect(row.run_time_ms).toBeUndefined();
  });

  it('emits every declared column, so the CSV header and the row cannot drift', () => {
    const row = normaliseRow({ EVENT_TYPE: 'URI' }, { seq: 1, attribution: 'seed', source: 'EventLogFile' });

    for (const column of EVENT_ROW_COLUMNS) {
      expect(Object.prototype.hasOwnProperty.call(row, column)).toBe(true);
    }
  });
});

describe('collapseAuraActions', () => {
  it('collapses a batch to one line with a count and a range', () => {
    const message = Array.from({ length: 100 }, (_, i) => `SelectableListDataProviderController/getItems=${i}`).join(';');

    expect(collapseAuraActions(message)).toBe('SelectableListDataProviderController/getItems x100 [0-99ms]');
  });

  it('keeps the range, which distinguishes a denial from real work', () => {
    // A uniform 0ms batch is fail-fast permission denial. A spread of hundreds of ms is the
    // database actually being queried. Collapsing to a count alone would erase the difference.
    const denied = collapseAuraActions('Ctrl/get=0;Ctrl/get=0;Ctrl/get=0');
    const worked = collapseAuraActions('Ctrl/get=94;Ctrl/get=410;Ctrl/get=210');

    expect(denied).toBe('Ctrl/get x3 [0-0ms]');
    expect(worked).toBe('Ctrl/get x3 [94-410ms]');
  });

  it('reports each distinct descriptor separately', () => {
    const summary = collapseAuraActions('A/one=10;B/two=20;A/one=30');

    expect(summary).toContain('A/one x2 [10-30ms]');
    expect(summary).toContain('B/two x1 [20-20ms]');
  });

  it('returns undefined for an empty or unparseable message rather than a misleading summary', () => {
    expect(collapseAuraActions('')).toBeUndefined();
    expect(collapseAuraActions('not an action list')).toBeUndefined();
    expect(collapseAuraActions(undefined)).toBeUndefined();
  });

  it('preserves the raw message alongside the collapse', () => {
    const message = 'Ctrl/get=10;Ctrl/get=20';
    const row = normaliseRow(
      { EVENT_TYPE: 'AuraRequest', ACTION_MESSAGE: message },
      { seq: 1, attribution: 'seed', source: 'EventLogFile' },
    );

    expect(row.aura_action_summary).toBe('Ctrl/get x2 [10-20ms]');
    expect(row.aura_action_message).toBe(message);
  });
});
