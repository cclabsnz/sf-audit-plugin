import type { ProbeProvenance } from '../probe/types.js';

export interface AutomationCounts {
  flows: number;
  triggers: number;
  approvals: number;
  workflowRules: number;
  total: number;
}

export interface StatusField {
  field: string;
  label: string;
  values: string[];
  /** True if matched by name (/status|stage|state|phase/i); false if inferred from an ordered value set. */
  matchedByName: boolean;
}

export interface AnchorSignals {
  automation: AutomationCounts;
  statusField: StatusField | null;
  totalRecords: number | null;
  created90d: number | null;
  /** In-degree: distinct other objects with a lookup/master-detail pointing at this object. */
  inboundReferences: number;
  /** Task/Event/EmailMessage attached over 90d; null if not computed for this object. */
  activityAttach: number | null;
  activityApproximate: boolean;
  historyTracking: boolean;
}

export interface AnchorCandidate {
  object: string;
  label: string;
  custom: boolean;
  /** Final weighted score in [0,1]. */
  score: number;
  /** Per-signal normalized-and-weighted contributions (sum ≈ score). */
  contributions: Record<string, number>;
  signals: AnchorSignals;
  /** Human-readable evidence lines. */
  evidence: string[];
}

export interface InstalledPackage {
  namespace: string | null;
  name: string;
  version: string | null;
}

export interface RecordTypeRef {
  object: string;
  developerName: string;
  label: string;
}

export interface StatusPicklistRef {
  object: string;
  field: string;
  values: string[];
}

/**
 * Domain fingerprint — the deterministic input a future classifier will consume. This
 * milestone emits it; nothing consumes it yet.
 */
export interface DomainFingerprint {
  version: 1;
  installedPackages: InstalledPackage[];
  clouds: string[];
  objectInventory: string[];
  statusPicklists: StatusPicklistRef[];
  recordTypes: RecordTypeRef[];
  apps: string[];
}

export interface DiscoverData {
  org: { orgId: string; name: string };
  anchors: AnchorCandidate[];
  totalObjectsAnalyzed: number;
  droppedObjects: number;
  fingerprint: DomainFingerprint;
  weights: Record<string, number>;
  notes: string[];
}

export interface DiscoverResult extends DiscoverData {
  version: 1;
  provenance: ProbeProvenance;
}
