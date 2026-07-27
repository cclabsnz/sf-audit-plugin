import type {
  LandscapeManifest,
  LandscapeManifestProvenance,
  L0Cluster,
  L1PerCluster,
  L2PerAnchor,
  LayoutCoord,
  CouplingGraphNode,
} from '@cclabsnz/sf-core';
import type { Cluster } from './clusters.js';
import { computeLayout, type LayoutEdge, type Point } from './layout.js';

/**
 * Build the landscape manifest's L0 (clusters) and L1 (per-cluster node coords). L2 lists
 * anchors with null process-graph refs; L3/L4 are reserved for the paid mining tier and the
 * viewer.
 *
 * The manifest is a navigation contract: a viewer can only zoom to what has coordinates, so
 * both levels are laid out **completely and independently of the report's top-N picture**.
 * L0 lays out the clusters against each other (where each domain sits in the landscape); L1
 * lays out each domain's own objects in its own coordinate space. These are deliberately
 * different spaces from the report's single top-N view — see `assembleCouplingArtifacts`.
 */
export function buildManifest(
  provenance: LandscapeManifestProvenance,
  clusters: Cluster[],
  edges: LayoutEdge[],
  nodes: CouplingGraphNode[],
  labelOf: (object: string) => string,
): LandscapeManifest {
  const nodeByName = new Map(nodes.map((n) => [n.object, n]));
  const clusterOf = new Map<string, string>();
  for (const c of clusters) for (const o of c.objects) clusterOf.set(o, c.id);

  // L0: lay the domains out against each other, linked where any coupling crosses between them.
  const landscapeLayout = computeLayout(
    clusters.map((c) => c.id),
    interClusterEdges(edges, clusterOf),
  );

  // L1: lay out each domain's own objects, from the couplings internal to that domain.
  const domainLayouts = new Map<string, Map<string, Point>>(
    clusters.map((c) => {
      const within = new Set(c.objects);
      const internal = edges.filter((e) => within.has(e.from) && within.has(e.to));
      return [c.id, computeLayout(c.objects, internal)];
    }),
  );

  const L0: L0Cluster[] = clusters.map((c) => ({
    id: c.id,
    label: labelOf(c.anchorObject),
    objects: c.objects,
    layout: landscapeLayout.get(c.id) ?? { x: 0, y: 0 },
    metrics: clusterMetrics(c, nodeByName),
  }));

  const L1: L1PerCluster[] = clusters.map((c) => ({
    clusterId: c.id,
    graphRef: `coupling-graph.json#${c.id}`,
    anchorObject: c.anchorObject,
    layout: coordMap(c.objects, domainLayouts.get(c.id) ?? new Map()),
  }));

  const L2: L2PerAnchor[] = clusters.map((c) => ({ anchorObject: c.anchorObject, processGraphRef: null }));

  return {
    version: 1,
    provenance,
    levels: {
      L0_landscape: { clusters: L0 },
      L1_domain: { perCluster: L1 },
      L2_process: { perAnchor: L2 },
      L3_transition: { reserved: true },
      L4_component: { flowSummaryRefs: [] },
    },
  };
}

function clusterMetrics(c: Cluster, nodeByName: Map<string, CouplingGraphNode>): L0Cluster['metrics'] {
  let automations = 0;
  let recordCount90d = 0;
  for (const o of c.objects) {
    const n = nodeByName.get(o);
    if (!n) continue;
    automations += n.automationCounts.flows + n.automationCounts.triggers + n.automationCounts.approvals;
    recordCount90d += n.recordCount90d;
  }
  return { objects: c.objects.length, automations, recordCount90d };
}

/** Distinct cluster-to-cluster links, for laying the landscape out. Deterministically ordered. */
function interClusterEdges(edges: LayoutEdge[], clusterOf: Map<string, string>): LayoutEdge[] {
  const seen = new Set<string>();
  const out: LayoutEdge[] = [];
  for (const e of edges) {
    const a = clusterOf.get(e.from);
    const b = clusterOf.get(e.to);
    if (a === undefined || b === undefined || a === b) continue;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ from: a, to: b });
  }
  return out.sort((x, y) => (x.from + x.to).localeCompare(y.from + y.to));
}

function coordMap(objects: string[], layout: Map<string, Point>): Record<string, LayoutCoord> {
  const out: Record<string, LayoutCoord> = {};
  for (const o of objects) {
    const p = layout.get(o);
    if (p) out[o] = { x: p.x, y: p.y };
  }
  return out;
}
