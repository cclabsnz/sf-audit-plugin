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
import type { Point } from './layout.js';

/**
 * Build the landscape manifest's L0 (clusters) and L1 (per-cluster node coords) from data the
 * map already computed. L2 lists anchors with null process-graph refs; L3/L4 are reserved for
 * the paid mining tier and the viewer. Layout coordinates are reused from the report layout so
 * the manifest and the HTML picture agree exactly.
 */
export function buildManifest(
  provenance: LandscapeManifestProvenance,
  clusters: Cluster[],
  layout: Map<string, Point>,
  nodes: CouplingGraphNode[],
  labelOf: (object: string) => string,
): LandscapeManifest {
  const nodeByName = new Map(nodes.map((n) => [n.object, n]));

  const L0: L0Cluster[] = clusters.map((c) => ({
    id: c.id,
    label: labelOf(c.anchorObject),
    objects: c.objects,
    layout: centroid(c.objects, layout),
    metrics: clusterMetrics(c, nodeByName),
  }));

  const L1: L1PerCluster[] = clusters.map((c) => ({
    clusterId: c.id,
    graphRef: `coupling-graph.json#${c.id}`,
    anchorObject: c.anchorObject,
    layout: coordMap(c.objects, layout),
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

function centroid(objects: string[], layout: Map<string, Point>): LayoutCoord {
  const pts = objects.map((o) => layout.get(o)).filter((p): p is Point => !!p);
  if (pts.length === 0) return { x: 0, y: 0 };
  const x = pts.reduce((s, p) => s + p.x, 0) / pts.length;
  const y = pts.reduce((s, p) => s + p.y, 0) / pts.length;
  return { x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 };
}

function coordMap(objects: string[], layout: Map<string, Point>): Record<string, LayoutCoord> {
  const out: Record<string, LayoutCoord> = {};
  for (const o of objects) {
    const p = layout.get(o);
    if (p) out[o] = { x: p.x, y: p.y };
  }
  return out;
}
