import { louvainCommunities } from './louvain.js';
export interface GraphEdgeLite {
  from: string;
  to: string;
  weight: number;
}

export interface Cluster {
  id: string;
  objects: string[];
  anchorObject: string;
}

export interface ClusterOptions {
  /**
   * Largest domain a consultant should be handed. Resolution is raised until every community
   * fits, or until raising it would only fragment the graph into singletons.
   */
  targetDomainSize?: number;
}

/**
 * Default ceiling on domain size. On a real 202-object org this lands ~24 domains with no
 * singletons; pushing smaller starts shedding isolated objects rather than finding structure.
 */
const DEFAULT_TARGET_DOMAIN_SIZE = 25;

/**
 * A graph with average degree below 2 is a forest — it has no cycles, and therefore no
 * community structure for modularity to find. (A forest has at most n-1 edges, so 2m/n < 2.)
 * Modularity shatters a chain into adjacent pairs at every resolution, so these are clustered
 * structurally instead.
 */
const FOREST_AVG_DEGREE = 2;

/**
 * A bridge is cut only if its weight is below this fraction of the median internal edge
 * weight on *both* sides — i.e. it is weak relative to the domains it joins, not merely the
 * lightest edge in the graph. An absolute "cut the minimum-weight bridge" rule shatters any
 * tree, because in a tree every edge is a bridge; a uniform-weight hub-and-spoke org (the
 * canonical Salesforce shape) would come back as N domains of one object each.
 */
const WEAK_BRIDGE_RATIO = 0.5;

/** Never shear off a side smaller than this — a one-object "domain" is not a useful answer. */
const MIN_SPLIT_SIZE = 2;

/**
 * Partition the coupling graph into domain clusters via connected components, splitting only
 * on bridges that are weak *relative to* the domains they join (see `WEAK_BRIDGE_RATIO`), so
 * a tenuous link doesn't fuse two real domains and a uniform-weight graph isn't shattered.
 * Deterministic and dependency-free (Tarjan bridge-finding + BFS components).
 */
export function clusterGraph(
  nodes: string[],
  edges: GraphEdgeLite[],
  score: (object: string) => number,
  opts: ClusterOptions = {},
): Cluster[] {
  if (nodes.length === 0) return [];

  // Pick the algorithm by density. Neither is valid across both regimes: modularity is
  // undefined on a forest, and bridge-cutting is useless on a dense graph (a real org has
  // ~2000 edges over ~200 objects and almost no bridges, so everything lands in one blob).
  const averageDegree = nodes.length > 0 ? (2 * edges.length) / nodes.length : 0;
  const groups =
    averageDegree < FOREST_AVG_DEGREE
      ? structuralComponents(nodes, edges)
      : modularityCommunities(nodes, edges, opts.targetDomainSize ?? DEFAULT_TARGET_DOMAIN_SIZE);

  return finalise(groups, score);
}

/**
 * Raise resolution until the largest community fits the target, stopping early if the graph
 * is only fragmenting (singletons appearing) rather than resolving real structure.
 */
function modularityCommunities(
  nodes: string[],
  edges: GraphEdgeLite[],
  targetDomainSize: number,
): string[][] {
  let best = louvainCommunities(nodes, edges, 1);
  for (const resolution of [1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) {
    if (best[0] !== undefined && best[0].length <= targetDomainSize) break;
    const attempt = louvainCommunities(nodes, edges, resolution);
    const singletons = attempt.filter((c) => c.length === 1).length;
    // Fragmenting more than a fifth of the graph into singletons is not structure.
    if (singletons > Math.max(2, attempt.length / 5)) break;
    best = attempt;
  }
  return best;
}

/** Connected components after cutting bridges that are weak relative to both sides. */
function structuralComponents(nodes: string[], edges: GraphEdgeLite[]): string[][] {
  const index = new Map(nodes.map((n, i) => [n, i]));
  const adj: number[][] = nodes.map(() => []);
  for (const e of edges) {
    const a = index.get(e.from);
    const b = index.get(e.to);
    if (a === undefined || b === undefined) continue;
    adj[a].push(b);
    adj[b].push(a);
  }

  const bridges = findBridges(nodes.length, adj);
  const cut = new Set<string>();
  // Sorted for determinism: the decision for one bridge never depends on iteration order,
  // but keeping the sweep ordered makes the behaviour reproducible and easy to reason about.
  for (const e of [...edges].sort(byEdgeKey(index))) {
    const a = index.get(e.from);
    const b = index.get(e.to);
    if (a === undefined || b === undefined) continue;
    const key = edgeKey(a, b);
    if (!bridges.has(key)) continue;
    if (isWeakBridge(e, key, a, b, nodes.length, adj, edges, index)) cut.add(key);
  }

  const keep: GraphEdgeLite[] = edges.filter((e) => {
    const a = index.get(e.from);
    const b = index.get(e.to);
    if (a === undefined || b === undefined) return true;
    return !cut.has(edgeKey(a, b));
  });

  return connectedComponents(nodes, keep);
}

/** Sort, anchor and number the groups. Deterministic for a given membership. */
function finalise(groups: string[][], score: (object: string) => number): Cluster[] {
  return groups
    .map((objects) => {
      const sorted = [...objects].sort();
      const anchorObject = sorted.reduce((best, o) => (score(o) > score(best) ? o : best), sorted[0]);
      return { objects: sorted, anchorObject };
    })
    .sort((a, b) => b.objects.length - a.objects.length || a.anchorObject.localeCompare(b.anchorObject))
    .map((c, i) => ({ id: `cluster-${i + 1}`, objects: c.objects, anchorObject: c.anchorObject }));
}

/** Order edges by their canonical key so the bridge sweep is reproducible. */
function byEdgeKey(index: Map<string, number>) {
  return (x: GraphEdgeLite, y: GraphEdgeLite): number => {
    const kx = edgeKey(index.get(x.from) ?? -1, index.get(x.to) ?? -1);
    const ky = edgeKey(index.get(y.from) ?? -1, index.get(y.to) ?? -1);
    return kx < ky ? -1 : kx > ky ? 1 : 0;
  };
}

/**
 * True if removing this bridge separates two sides that are each substantial and each
 * internally much more strongly coupled than the bridge itself.
 */
function isWeakBridge(
  bridge: GraphEdgeLite,
  key: string,
  a: number,
  b: number,
  nodeCount: number,
  adj: number[][],
  edges: GraphEdgeLite[],
  index: Map<string, number>,
): boolean {
  const sideA = reachableWithout(a, key, nodeCount, adj);
  if (sideA.size < MIN_SPLIT_SIZE) return false;
  const sideB = reachableWithout(b, key, nodeCount, adj);
  if (sideB.size < MIN_SPLIT_SIZE) return false;

  const medianA = medianInternalWeight(sideA, edges, index);
  const medianB = medianInternalWeight(sideB, edges, index);
  // A side with no internal edges gives us nothing to compare against — don't guess.
  if (medianA === null || medianB === null) return false;

  return bridge.weight < WEAK_BRIDGE_RATIO * medianA && bridge.weight < WEAK_BRIDGE_RATIO * medianB;
}

/** Nodes reachable from `start` when the given edge is removed. */
function reachableWithout(start: number, excludedKey: string, nodeCount: number, adj: number[][]): Set<number> {
  const seen = new Array<boolean>(nodeCount).fill(false);
  const out = new Set<number>();
  const queue = [start];
  seen[start] = true;
  while (queue.length > 0) {
    const u = queue.shift()!;
    out.add(u);
    for (const v of adj[u]) {
      if (seen[v] || edgeKey(u, v) === excludedKey) continue;
      seen[v] = true;
      queue.push(v);
    }
  }
  return out;
}

/** Median weight of edges with both endpoints inside `side`; null if there are none. */
function medianInternalWeight(
  side: Set<number>,
  edges: GraphEdgeLite[],
  index: Map<string, number>,
): number | null {
  const weights: number[] = [];
  for (const e of edges) {
    const a = index.get(e.from);
    const b = index.get(e.to);
    if (a === undefined || b === undefined) continue;
    if (side.has(a) && side.has(b)) weights.push(e.weight);
  }
  if (weights.length === 0) return null;
  weights.sort((x, y) => x - y);
  const mid = weights.length >> 1;
  return weights.length % 2 === 1 ? weights[mid] : (weights[mid - 1] + weights[mid]) / 2;
}

function findBridges(n: number, adj: number[][]): Set<string> {
  const disc = new Array<number>(n).fill(-1);
  const low = new Array<number>(n).fill(-1);
  const bridges = new Set<string>();
  let timer = 0;

  // Iterative DFS to avoid stack overflow on large graphs.
  for (let s = 0; s < n; s++) {
    if (disc[s] !== -1) continue;
    const stack: Array<{ u: number; parent: number; i: number }> = [{ u: s, parent: -1, i: 0 }];
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const { u, parent } = frame;
      if (frame.i === 0) {
        disc[u] = low[u] = timer++;
      }
      if (frame.i < adj[u].length) {
        const v = adj[u][frame.i];
        frame.i++;
        if (v === parent) continue;
        if (disc[v] === -1) {
          stack.push({ u: v, parent: u, i: 0 });
        } else {
          low[u] = Math.min(low[u], disc[v]);
        }
      } else {
        stack.pop();
        if (parent !== -1) {
          low[parent] = Math.min(low[parent], low[u]);
          if (low[u] > disc[parent]) bridges.add(edgeKey(parent, u));
        }
      }
    }
  }
  return bridges;
}

function connectedComponents(nodes: string[], edges: GraphEdgeLite[]): string[][] {
  const index = new Map(nodes.map((n, i) => [n, i]));
  const adj: number[][] = nodes.map(() => []);
  for (const e of edges) {
    const a = index.get(e.from)!;
    const b = index.get(e.to)!;
    adj[a].push(b);
    adj[b].push(a);
  }
  const seen = new Array<boolean>(nodes.length).fill(false);
  const out: string[][] = [];
  for (let s = 0; s < nodes.length; s++) {
    if (seen[s]) continue;
    const comp: string[] = [];
    const queue = [s];
    seen[s] = true;
    while (queue.length > 0) {
      const u = queue.shift()!;
      comp.push(nodes[u]);
      for (const v of adj[u]) if (!seen[v]) {
        seen[v] = true;
        queue.push(v);
      }
    }
    out.push(comp);
  }
  return out;
}

function edgeKey(a: number, b: number): string {
  return a < b ? `${a}-${b}` : `${b}-${a}`;
}
