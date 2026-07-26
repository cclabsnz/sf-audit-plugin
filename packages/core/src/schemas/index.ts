// Typed interfaces for the OrgIntel IR contracts. The authoritative JSON Schema
// files live in `packages/core/schemas/*.schema.json`; these interfaces mirror them.
// Version fields start at 1 and are the product's stable contract.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// coupling-graph.schema.json (v1) — emitted by `intel map`
// ---------------------------------------------------------------------------
export type EvidenceTier = 'A' | 'B' | 'C' | 'D';
export type CouplingOperation = 'read' | 'create' | 'update' | 'delete';
export type CouplingConfidence = 'high' | 'approximate';

export interface CouplingGraphProvenance {
  tool: 'orgintel';
  toolVersion: string;
  generatedAt: string;
  orgId: string;
  evidenceTier: EvidenceTier;
}

export interface CouplingGraphNode {
  object: string;
  custom: boolean;
  automationCounts: { flows: number; triggers: number; approvals: number };
  recordCount90d: number;
}

export interface CouplingComponentRef {
  type: string;
  name: string;
  confidence: CouplingConfidence;
}

export interface CouplingGraphEdge {
  from: string;
  to: string;
  weight: number;
  operations: CouplingOperation[];
  components: CouplingComponentRef[];
}

export interface CouplingGraph {
  version: 1;
  provenance: CouplingGraphProvenance;
  nodes: CouplingGraphNode[];
  edges: CouplingGraphEdge[];
}

// ---------------------------------------------------------------------------
// process-graph.schema.json (v1) — reserved for the paid mining/conformance tier
// ---------------------------------------------------------------------------
export type ProcessNodeKind = 'state' | 'automation' | 'human' | 'integration';

export interface ProcessNode {
  id: string;
  kind: ProcessNodeKind;
  label: string;
  object?: string;
}

export interface ProcessObserved {
  count: number;
  p50_mins: number;
  error_rate: number;
}

export interface ProcessEdge {
  from: string;
  to: string;
  trigger: string;
  observed?: ProcessObserved;
}

export interface ProcessReferenceModel {
  id: string | null;
  version: string | null;
  source: string | null;
}

export interface ProcessGraphProvenance {
  tool: 'orgintel';
  toolVersion: string;
  generatedAt: string;
  orgId: string;
  referenceModel?: ProcessReferenceModel;
}

export interface ProcessGraph {
  version: 1;
  anchorObject: string;
  provenance: ProcessGraphProvenance;
  nodes: ProcessNode[];
  edges: ProcessEdge[];
}

// ---------------------------------------------------------------------------
// landscape-manifest.schema.json (v1) — semantic-zoom navigation contract
// ---------------------------------------------------------------------------
export interface LayoutCoord {
  x: number;
  y: number;
}

export interface LandscapeManifestProvenance {
  tool: 'orgintel';
  toolVersion: string;
  generatedAt: string;
  orgId: string;
}

export interface L0Cluster {
  id: string;
  label: string;
  objects: string[];
  layout: LayoutCoord;
  metrics: { objects: number; automations: number; recordCount90d: number };
}

export interface L1PerCluster {
  clusterId: string;
  graphRef: string;
  anchorObject: string;
  layout: Record<string, LayoutCoord>;
}

export interface L2PerAnchor {
  anchorObject: string;
  processGraphRef: string | null;
}

export interface LandscapeManifest {
  version: 1;
  provenance: LandscapeManifestProvenance;
  levels: {
    L0_landscape: { clusters: L0Cluster[] };
    L1_domain: { perCluster: L1PerCluster[] };
    L2_process: { perAnchor: L2PerAnchor[] };
    L3_transition: { reserved: true };
    L4_component: { flowSummaryRefs: string[] };
  };
}

// ---------------------------------------------------------------------------
// Schema file access — resolves `<packageRoot>/schemas` from both lib/ (compiled)
// and src/ (ts-jest), mirroring the font-asset resolution in report/fonts.ts.
// ---------------------------------------------------------------------------
const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, '..', '..', 'schemas');

export type SchemaName = 'coupling-graph' | 'process-graph' | 'landscape-manifest';

/** Absolute path to a schema JSON file. */
export function schemaPath(name: SchemaName): string {
  return join(SCHEMA_DIR, `${name}.schema.json`);
}

/** Parsed JSON Schema object for the given contract. */
export function loadSchema(name: SchemaName): unknown {
  return JSON.parse(readFileSync(schemaPath(name), 'utf8'));
}
