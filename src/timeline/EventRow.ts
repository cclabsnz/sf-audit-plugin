import type { Attribution } from './CorrelationEngine.js';

/** Which capture the row came out of. */
export type EventSource = 'EventLogFile' | 'RealTimeEventMonitoring';

/**
 * One row of the timeline, in the shape every source is mapped into.
 *
 * Ordered identity → attribution → causation → timing → payload → source-specific, so a reader
 * scanning left to right meets "who and why is this here" before "what did it do".
 *
 * Everything is optional except the few fields every source can supply. A blank column is
 * informative in itself: `rows_processed` is empty for every EventLogFile row because no ELF
 * type records it, and that absence is exactly why the real-time objects matter.
 */
export interface EventRow {
  // --- identity -----------------------------------------------------------------
  seq: number;
  timestamp_utc: string;
  event_type: string;
  source: EventSource;
  attribution: Attribution;

  client_ip?: string;
  request_id?: string;
  session_key?: string;
  login_key?: string;
  user_id?: string;
  user_type?: string;
  is_guest?: boolean;

  // --- causation ----------------------------------------------------------------
  // Not in the original column set. Without these the timeline shows what an actor did
  // alongside what else was happening, but not what their actions set off.
  /** The save transaction this row belongs to — a cascade shares one. */
  transaction_id?: string;
  /** This row's own event identity, which later events point back at. */
  event_identifier?: string;
  /** The event that caused this one. */
  related_event_identifier?: string;
  /** Object the row acted on, where the source names one. */
  entity_name?: string;
  /** Records the row touched, where the source names them. */
  record_ids?: string;
  /** The page this request came from — chains navigation into a path. */
  referrer_uri?: string;
  /** Actor fingerprint. Weak alone, but it survives an address change. */
  user_agent?: string;
  /** Apex execution context: trigger, batch, anonymous, and so on. */
  quiddity?: string;

  // --- timing and outcome -------------------------------------------------------
  run_time_ms?: number;
  response_bytes?: number;
  page_name?: string;
  http_method?: string;
  is_error?: boolean;
  uri?: string;
  entry_point?: string;

  // --- query --------------------------------------------------------------------
  query_type?: string;
  sql_id?: string;

  // --- did records leave --------------------------------------------------------
  // First-class rather than a blob: these are the fields that answer the question an
  // investigation actually asks. Populated only from real-time objects.
  rows_processed?: number;
  queried_entities?: string;
  records_returned?: string;
  list_view_name?: string;
  list_view_scope?: string;
  filter_criteria?: string;

  // --- graphql ------------------------------------------------------------------
  graphql_operation?: string;
  graphql_query?: string;
  graphql_exception?: string;

  // --- aura ---------------------------------------------------------------------
  /** Batched actions collapsed to one readable line. */
  aura_action_summary?: string;
  /** The raw message, kept so the collapse is never the only record. */
  aura_action_message?: string;

  source_file?: string;
}

/** Column order for tabular output. The single source of truth for CSV headers. */
export const EVENT_ROW_COLUMNS: ReadonlyArray<keyof EventRow> = [
  'seq', 'timestamp_utc', 'event_type', 'source', 'attribution',
  'client_ip', 'request_id', 'session_key', 'login_key', 'user_id', 'user_type', 'is_guest',
  'transaction_id', 'event_identifier', 'related_event_identifier',
  'entity_name', 'record_ids', 'referrer_uri', 'user_agent', 'quiddity',
  'run_time_ms', 'response_bytes', 'page_name', 'http_method', 'is_error', 'uri', 'entry_point',
  'query_type', 'sql_id',
  'rows_processed', 'queried_entities', 'records_returned', 'list_view_name', 'list_view_scope',
  'filter_criteria',
  'graphql_operation', 'graphql_query', 'graphql_exception',
  'aura_action_summary', 'aura_action_message', 'source_file',
];
