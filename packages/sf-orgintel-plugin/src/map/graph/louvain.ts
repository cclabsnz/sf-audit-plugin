export interface WeightedEdge {
  from: string;
  to: string;
  weight: number;
}

/**
 * Louvain modularity communities, with a resolution parameter.
 *
 * Standard two-phase Louvain: repeatedly move nodes to the neighbouring community that most
 * improves modularity, then contract each community to a super-node and repeat on the smaller
 * graph. Higher `resolution` yields smaller, more numerous communities.
 *
 * Determinism is a product claim, so every ordering here is explicit: nodes are indexed in
 * sorted order, candidate communities are visited in ascending index, and a move needs to beat
 * the incumbent by more than an epsilon. Same graph in, same communities out — regardless of
 * the order the caller supplied nodes or edges.
 */
export function louvainCommunities(
  nodes: readonly string[],
  edges: readonly WeightedEdge[],
  resolution = 1,
): string[][] {
  const ordered = [...nodes].sort();
  const n = ordered.length;
  if (n === 0) return [];

  const index = new Map(ordered.map((name, i) => [name, i]));
  // Adjacency of the current (possibly contracted) level.
  let adjacency = buildAdjacency(n, edges, index);
  let selfLoops = new Array<number>(n).fill(0);
  // members[i] = original node names collapsed into super-node i.
  let members: string[][] = ordered.map((name) => [name]);

  const total2m = adjacency.reduce((sum, row) => sum + [...row.values()].reduce((s, w) => s + w, 0), 0);
  if (total2m === 0) return members;

  for (let level = 0; level < 10; level++) {
    const assignment = localMoving(adjacency, selfLoops, total2m, resolution);
    const communityCount = new Set(assignment).size;
    if (communityCount === adjacency.length) break; // nothing merged — converged

    const contracted = contract(adjacency, selfLoops, assignment, members);
    adjacency = contracted.adjacency;
    selfLoops = contracted.selfLoops;
    members = contracted.members;
    if (adjacency.length <= 1) break;
  }

  return members.map((m) => m.slice().sort()).sort((a, b) => b.length - a.length || a[0].localeCompare(b[0]));
}

function buildAdjacency(n: number, edges: readonly WeightedEdge[], index: Map<string, number>): Array<Map<number, number>> {
  const adjacency: Array<Map<number, number>> = Array.from({ length: n }, () => new Map());
  for (const edge of edges) {
    const a = index.get(edge.from);
    const b = index.get(edge.to);
    if (a === undefined || b === undefined || a === b) continue;
    adjacency[a].set(b, (adjacency[a].get(b) ?? 0) + edge.weight);
    adjacency[b].set(a, (adjacency[b].get(a) ?? 0) + edge.weight);
  }
  return adjacency;
}

/** One local-moving phase: returns the community index chosen for each node. */
function localMoving(
  adjacency: Array<Map<number, number>>,
  selfLoops: number[],
  total2m: number,
  resolution: number,
): number[] {
  const n = adjacency.length;
  const degree = adjacency.map((row, i) => [...row.values()].reduce((s, w) => s + w, 0) + 2 * selfLoops[i]);
  const community = Array.from({ length: n }, (_, i) => i);
  const communityDegree = degree.slice();

  for (let pass = 0; pass < 20; pass++) {
    let moved = false;
    for (let node = 0; node < n; node++) {
      const from = community[node];
      communityDegree[from] -= degree[node];

      const linksTo = new Map<number, number>();
      for (const [neighbour, weight] of adjacency[node]) {
        linksTo.set(community[neighbour], (linksTo.get(community[neighbour]) ?? 0) + weight);
      }

      let best = from;
      let bestGain = (linksTo.get(from) ?? 0) - (resolution * communityDegree[from] * degree[node]) / total2m;
      for (const candidate of [...linksTo.keys()].sort((a, b) => a - b)) {
        const gain = linksTo.get(candidate)! - (resolution * communityDegree[candidate] * degree[node]) / total2m;
        if (gain > bestGain + 1e-12) {
          bestGain = gain;
          best = candidate;
        }
      }

      communityDegree[best] += degree[node];
      if (best !== from) {
        community[node] = best;
        moved = true;
      }
    }
    if (!moved) break;
  }
  return community;
}

/** Collapse each community into a super-node, preserving internal weight as a self-loop. */
function contract(
  adjacency: Array<Map<number, number>>,
  selfLoops: number[],
  assignment: number[],
  members: string[][],
): { adjacency: Array<Map<number, number>>; selfLoops: number[]; members: string[][] } {
  // Renumber communities to a dense 0..k-1 range, in ascending original index for determinism.
  const remap = new Map<number, number>();
  for (const c of [...new Set(assignment)].sort((a, b) => a - b)) remap.set(c, remap.size);
  const k = remap.size;

  const nextAdjacency: Array<Map<number, number>> = Array.from({ length: k }, () => new Map());
  const nextSelfLoops = new Array<number>(k).fill(0);
  const nextMembers: string[][] = Array.from({ length: k }, () => []);

  assignment.forEach((c, node) => {
    const target = remap.get(c)!;
    nextMembers[target].push(...members[node]);
    nextSelfLoops[target] += selfLoops[node];
  });

  for (let node = 0; node < adjacency.length; node++) {
    const a = remap.get(assignment[node])!;
    for (const [neighbour, weight] of adjacency[node]) {
      const b = remap.get(assignment[neighbour])!;
      if (a === b) {
        if (node < neighbour) nextSelfLoops[a] += weight;
      } else {
        nextAdjacency[a].set(b, (nextAdjacency[a].get(b) ?? 0) + weight / 2);
        nextAdjacency[b].set(a, (nextAdjacency[b].get(a) ?? 0) + weight / 2);
      }
    }
  }

  return { adjacency: nextAdjacency, selfLoops: nextSelfLoops, members: nextMembers };
}
