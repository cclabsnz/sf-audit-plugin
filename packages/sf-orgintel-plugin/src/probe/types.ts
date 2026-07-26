import type { EvidenceTier } from '@cclabsnz/sf-core';

export type { EvidenceTier };

// --- Org basics ---------------------------------------------------------------
export interface OrgBasics {
  orgId: string;
  name: string;
  /** OrganizationType, e.g. "Enterprise Edition", "Developer Edition". */
  organizationType: string;
  isSandbox: boolean;
  instanceUrl: string;
  apiVersion: string;
  namespace: string | null;
}

// --- Event Monitoring ---------------------------------------------------------
export type EmLevel = 'none' | 'free-tier' | 'full';
export type EventLogAccessStatus = 'ok' | 'no-permission' | 'not-enabled' | 'unknown';

export interface EventMonitoringCoverage {
  level: EmLevel;
  access: EventLogAccessStatus;
  /** Distinct Interval values observed over the sample window (e.g. "Daily", "Hourly"). */
  intervals: string[];
  /** Distinct EventType values observed (bounded sample). */
  eventTypes: string[];
  eventTypeCount: number;
  note: string;
}

// --- Field history ------------------------------------------------------------
export interface ObjectHistoryCoverage {
  object: string;
  custom: boolean;
  historyTrackingEnabled: boolean;
  /**
   * Count of fields with recorded history changes over the last 12 months. This is a
   * queryable lower bound on the set of tracked fields (fields tracked but unchanged in
   * the window are not observable without the Metadata API); labelled approximate.
   */
  trackedFieldCount: number | null;
  trackedFields: string[];
  /** trackedFieldCount is at/above the 20-field history-tracking cap. */
  atCap: boolean;
  note?: string;
}

export interface FieldHistoryCoverage {
  objects: ObjectHistoryCoverage[];
  trackedObjectCount: number;
  /** FieldHistoryArchive (Field Audit Trail / Shield) present and queryable. */
  fieldAuditTrail: boolean;
  note: string;
}

// --- Behavioral tables --------------------------------------------------------
export type TableAccess = 'ok' | 'no-access' | 'not-present';

export interface BehavioralTable {
  name: string;
  access: TableAccess;
  /** Rows created in the last 12 months; null when the table is inaccessible/absent. */
  rowCount12mo: number | null;
  /** Supplementary bounded counts, e.g. FlowInterview paused/error. */
  extra?: Record<string, number>;
  note?: string;
}

export interface BehavioralTablesCoverage {
  tables: BehavioralTable[];
}

// --- Coverage summary + recommendations --------------------------------------
export type CoverageStatus = 'full' | 'partial' | 'none';

export interface CoverageRow {
  source: string;
  status: CoverageStatus;
  detail: string;
}

export type RecommendationPriority = 'high' | 'medium' | 'low';

export interface Recommendation {
  title: string;
  detail: string;
  priority: RecommendationPriority;
}

// --- Result -------------------------------------------------------------------
/** Deterministic probe output — a pure function of the org's current state. */
export interface ProbeData {
  org: OrgBasics;
  eventMonitoring: EventMonitoringCoverage;
  fieldHistory: FieldHistoryCoverage;
  behavioralTables: BehavioralTablesCoverage;
  evidenceTier: EvidenceTier;
  coverage: CoverageRow[];
  recommendations: Recommendation[];
}

export interface ProbeProvenance {
  tool: 'orgintel';
  toolVersion: string;
  generatedAt: string;
  orgId: string;
}

/** ProbeData wrapped with (non-deterministic) provenance for emitted artifacts. */
export interface ProbeResult extends ProbeData {
  version: 1;
  provenance: ProbeProvenance;
}
