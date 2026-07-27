import type {
  CouplingGraph,
  CouplingGraphEdge,
  CouplingGraphProvenance,
  LandscapeManifest,
  LandscapeManifestProvenance,
} from '@cclabsnz/sf-core';
import type { FlowSummary } from './flow/flowTypes.js';
import type { ApexClassInput, ApexTriggerInput } from './apex/apexTypes.js';
import { deriveFlowEdges } from './flow/flowEdges.js';
import { deriveApexEdges } from './apex/apexEdges.js';
import { mergeEdges, buildNodes, type NodeInfo } from './graph/couplingGraph.js';
import { clusterGraph, type Cluster } from './graph/clusters.js';
import { computeLayout, type Point } from './graph/layout.js';
import { buildManifest } from './graph/manifest.js';

export interface AssembleInput {
  flowSummaries: FlowSummary[];
  apexClasses: ApexClassInput[];
  apexTriggers: ApexTriggerInput[];
  knownObjects: Set<string>;
  nodeInfo: (object: string) => NodeInfo;
  labelOf: (object: string) => string;
  couplingProvenance: CouplingGraphProvenance;
  manifestProvenance: LandscapeManifestProvenance;
  /** Number of top-ranked nodes to lay out for the visual (default 20). */
  topLayout?: number;
  notes?: string[];
}

export interface MapArtifacts {
  couplingGraph: CouplingGraph;
  manifest: LandscapeManifest;
  clusters: Cluster[];
  layout: Map<string, Point>;
  notes: string[];
}

/** Pure assembly: flow + apex edges -> merged coupling graph, clusters, layout, and manifest. */
export function assembleCouplingArtifacts(input: AssembleInput): MapArtifacts {
  const notes = [...(input.notes ?? [])];

  const flow = deriveFlowEdges(input.flowSummaries);
  if (flow.missingSubflows.length > 0) {
    notes.push(`Subflows referenced but not retrieved (touches not inherited): ${flow.missingSubflows.join(', ')}.`);
  }
  const apexEdges = deriveApexEdges(input.apexClasses, input.apexTriggers, input.knownObjects);

  const edges = mergeEdges([...flow.edges, ...apexEdges]);
  const nodes = buildNodes(edges, input.nodeInfo);

  // Weighted-degree + automation score, for cluster anchors and layout ranking.
  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.from, (degree.get(e.from) ?? 0) + e.weight);
    degree.set(e.to, (degree.get(e.to) ?? 0) + e.weight);
  }
  const score = (o: string): number => {
    const d = degree.get(o) ?? 0;
    const a = input.nodeInfo(o).automationCounts;
    return d + a.flows + a.triggers + a.approvals;
  };

  const nodeNames = nodes.map((n) => n.object);
  const clusters = clusterGraph(nodeNames, edges, score);

  // Lay out the top-ranked nodes for the report picture only. The manifest lays itself out
  // completely and separately (see buildManifest) — a viewer must be able to zoom to every
  // domain, not just the ones that fit in the report's top-N view.
  const topLayout = input.topLayout ?? 20;
  const topNodes = [...nodeNames].sort((a, b) => score(b) - score(a) || a.localeCompare(b)).slice(0, topLayout);
  const topSet = new Set(topNodes);
  const layoutEdges = edges.filter((e) => topSet.has(e.from) && topSet.has(e.to));
  const layout = computeLayout(topNodes, layoutEdges);

  const couplingGraph: CouplingGraph = {
    version: 1,
    provenance: input.couplingProvenance,
    nodes,
    edges,
  };

  const manifest = buildManifest(input.manifestProvenance, clusters, edges, nodes, input.labelOf);

  return { couplingGraph, manifest, clusters, layout, notes };
}

/** Top coupled object pairs (the org's process backbones). */
export function topCouplingPairs(graph: CouplingGraph, n = 20): CouplingGraphEdge[] {
  return graph.edges.slice(0, n);
}
