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

/**
 * Partition the coupling graph into domain clusters via connected components, splitting on
 * weak bridges: bridge edges (whose removal disconnects the graph) with the minimum weight
 * are cut first, so tenuous single-component links don't fuse two real domains. Deterministic
 * and dependency-free (Tarjan bridge-finding + BFS components).
 */
export function clusterGraph(
  nodes: string[],
  edges: GraphEdgeLite[],
  score: (object: string) => number,
): Cluster[] {
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
  // Cut only the weakest bridges (weight === minimum bridge weight).
  const bridgeWeights = edges
    .filter((e) => bridges.has(edgeKey(index.get(e.from)!, index.get(e.to)!)))
    .map((e) => e.weight);
  const minBridgeWeight = bridgeWeights.length > 0 ? Math.min(...bridgeWeights) : Infinity;

  const keep: GraphEdgeLite[] = edges.filter((e) => {
    const k = edgeKey(index.get(e.from)!, index.get(e.to)!);
    return !(bridges.has(k) && e.weight <= minBridgeWeight);
  });

  const components = connectedComponents(nodes, keep);
  const clusters = components
    .map((objects) => {
      const sorted = [...objects].sort();
      const anchorObject = sorted.reduce((best, o) => (score(o) > score(best) ? o : best), sorted[0]);
      return { objects: sorted, anchorObject };
    })
    .sort((a, b) => b.objects.length - a.objects.length || a.anchorObject.localeCompare(b.anchorObject));

  return clusters.map((c, i) => ({ id: `cluster-${i + 1}`, objects: c.objects, anchorObject: c.anchorObject }));
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
