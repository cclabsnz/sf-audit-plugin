import { EVENT_ROW_COLUMNS, type EventRow, type EventSource } from './EventRow.js';
import { joinKeysOf } from './JoinKeys.js';
import type { Attribution } from './CorrelationEngine.js';

export interface NormaliseContext {
  seq: number;
  attribution: Attribution;
  source: EventSource;
}

/** Blank is absent. An empty string in a column means the source had nothing, not that it said "". */
function text(...candidates: unknown[]): string | undefined {
  for (const value of candidates) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return undefined;
}

/** A number, or nothing. Never a guess: an unparseable value is absent, not zero. */
function num(...candidates: unknown[]): number | undefined {
  for (const value of candidates) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() !== '') {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

/**
 * Field aliases, one table rather than a branch per event type.
 *
 * There are more than sixty event types and Salesforce keeps adding them. A switch would need a
 * case for each, and the type it does not have a case for would vanish — which for a forensic
 * tool is the worst outcome, because the absence looks like evidence. Every row is mapped
 * through the same table, so an unrecognised type still yields its common fields and simply
 * leaves the specific ones blank.
 *
 * Each entry lists the spellings a value appears under, in preference order. EventLogFile uses
 * SHOUTING_SNAKE and real-time objects use PascalCase, often for the same concept.
 */
const TEXT_FIELDS: Partial<Record<keyof EventRow, string[]>> = {
  event_type: ['EVENT_TYPE', 'EventType'],
  timestamp_utc: ['TIMESTAMP_DERIVED', 'TIMESTAMP', 'EventDate', 'CreatedDate'],
  user_type: ['USER_TYPE', 'UserType'],
  entity_name: ['ENTITY_NAME', 'EntityName', 'QueriedEntities'],
  record_ids: ['RECORD_ID', 'RecordIds', 'RecordId'],
  referrer_uri: ['REFERRER_URI', 'REFERRER'],
  user_agent: ['USER_AGENT', 'UserAgent', 'Browser'],
  quiddity: ['QUIDDITY', 'Quiddity'],
  page_name: ['PAGE_NAME', 'PAGE_APP_NAME', 'Page'],
  http_method: ['METHOD', 'HTTP_METHOD', 'RequestType'],
  uri: ['URI', 'Uri', 'URL'],
  entry_point: ['ENTRY_POINT', 'EntryPoint'],
  query_type: ['QUERY_TYPE', 'QueryType', 'Operation'],
  sql_id: ['SQL_ID', 'QueryId'],
  queried_entities: ['QueriedEntities', 'QUERIED_ENTITIES'],
  records_returned: ['RecordIds', 'RECORDS_RETURNED', 'Records'],
  list_view_name: ['Name', 'LIST_VIEW_NAME', 'ListViewName'],
  list_view_scope: ['Scope', 'LIST_VIEW_SCOPE'],
  filter_criteria: ['FilterCriteria', 'FILTER_CRITERIA', 'Filter'],
  graphql_operation: ['OPERATION_NAME', 'GraphQLOperation'],
  graphql_query: ['QUERY', 'GraphQLQuery'],
  graphql_exception: ['EXCEPTION_MESSAGE', 'GraphQLException'],
  aura_action_message: ['ACTION_MESSAGE'],
  source_file: ['SOURCE_FILE', '__sourceFile'],
};

const NUMBER_FIELDS: Partial<Record<keyof EventRow, string[]>> = {
  run_time_ms: ['RUN_TIME', 'RunTime', 'EXEC_TIME'],
  response_bytes: ['RESPONSE_SIZE', 'ResponseSize', 'BYTES'],
  rows_processed: ['RowsProcessed', 'ROWS_PROCESSED', 'NUMBER_OF_RECORDS'],
};

/** Real-time objects supply the record-count fields; no EventLogFile type records them. */
const RTE_ONLY: ReadonlyArray<keyof EventRow> = [
  'rows_processed', 'records_returned', 'list_view_name', 'list_view_scope', 'filter_criteria',
];

/**
 * Collapse a batch of Aura actions into one readable line.
 *
 * A single request can carry hundreds of action invocations, and printed raw they bury the
 * timeline. The count alone would not do: the min–max range is the finding. A batch that is
 * uniformly 0ms is fail-fast permission denial — the actor was refused. A batch spread across
 * hundreds of milliseconds is the database being queried, which is the actor getting data.
 * Collapsing to a count would erase the difference between an attempt and a success.
 */
export function collapseAuraActions(message: string | undefined): string | undefined {
  if (!message) return undefined;

  const timings = new Map<string, { count: number; min: number; max: number }>();
  for (const [, descriptor, ms] of message.matchAll(/([A-Za-z0-9_$./-]+)\s*=\s*(\d+)/g)) {
    const value = Number(ms);
    const seen = timings.get(descriptor);
    if (seen) {
      seen.count++;
      seen.min = Math.min(seen.min, value);
      seen.max = Math.max(seen.max, value);
    } else {
      timings.set(descriptor, { count: 1, min: value, max: value });
    }
  }

  if (timings.size === 0) return undefined;
  return [...timings]
    .map(([descriptor, t]) => `${descriptor} x${t.count} [${t.min}-${t.max}ms]`)
    .join('; ');
}

/**
 * Map one raw row into the unified shape.
 *
 * Every declared column is present on the result, set to `undefined` where the source had
 * nothing. That keeps the CSV header and the row in lockstep — a column that only materialises
 * when populated shifts every value to its left the moment a source omits it.
 */
export function normaliseRow(raw: Record<string, unknown>, ctx: NormaliseContext): EventRow {
  const keys = joinKeysOf(raw);
  const isRte = ctx.source === 'RealTimeEventMonitoring';

  const row = {} as Record<string, unknown>;
  for (const column of EVENT_ROW_COLUMNS) row[column] = undefined;

  row.seq = ctx.seq;
  row.attribution = ctx.attribution;
  row.source = ctx.source;

  for (const [column, aliases] of Object.entries(TEXT_FIELDS)) {
    if (!isRte && RTE_ONLY.includes(column as keyof EventRow)) continue;
    row[column] = text(...aliases.map((a) => raw[a]));
  }
  for (const [column, aliases] of Object.entries(NUMBER_FIELDS)) {
    if (!isRte && RTE_ONLY.includes(column as keyof EventRow)) continue;
    row[column] = num(...aliases.map((a) => raw[a]));
  }

  // Join keys come from the one place that already applies the blank rule, so the timeline's
  // columns and the correlation that produced them cannot disagree about what a row's keys are.
  row.client_ip = keys.clientIp;
  row.request_id = keys.requestId;
  row.session_key = keys.sessionKey;
  row.login_key = keys.loginKey;
  row.user_id = keys.userId;
  row.transaction_id = keys.transactionId;
  row.event_identifier = keys.eventIdentifier;
  row.related_event_identifier = keys.relatedEventIdentifier;

  row.event_type = row.event_type ?? 'Unknown';
  row.timestamp_utc = row.timestamp_utc ?? '';
  row.is_guest = row.user_type === undefined ? undefined : /guest/i.test(String(row.user_type));
  row.is_error = errorFlag(raw);
  row.aura_action_summary = collapseAuraActions(row.aura_action_message as string | undefined);

  return row as unknown as EventRow;
}

/** Several types spell failure differently; none of them spell it consistently. */
function errorFlag(raw: Record<string, unknown>): boolean | undefined {
  const status = text(raw.STATUS_CODE, raw.HTTP_STATUS_CODE, raw.StatusCode);
  if (status !== undefined) {
    const code = Number(status);
    if (Number.isFinite(code)) return code >= 400;
  }
  const explicit = text(raw.IS_ERROR, raw.EXCEPTION_MESSAGE, raw.GraphQLException);
  if (explicit === undefined) return undefined;
  return explicit.toLowerCase() !== 'false' && explicit !== '0';
}
