import { describe, it, expect } from '@jest/globals';
import { clusterGraph, type GraphEdgeLite } from '../../../src/map/graph/clusters.js';

/**
 * Domain clustering must survive the topologies real Salesforce orgs actually have — both the
 * sparse ones (a small org is often a tree) and the dense ones (a mature org's coupling graph
 * has an average degree above 20).
 *
 * No single algorithm covers both. Modularity is undefined on a forest: a chain has no
 * community structure, and modularity optimisation shatters it into adjacent pairs at every
 * resolution. Bridge-cutting is undefined on a dense graph: with 2000+ edges over 200 nodes
 * there are almost no bridges, so it returns one giant blob. The implementation therefore
 * selects by density — see `clusterGraph`.
 */

const e = (from: string, to: string, weight = 1): GraphEdgeLite => ({ from, to, weight });
const flat = (): number => 1;
const sizes = (cs: Array<{ objects: string[] }>): number[] => cs.map((c) => c.objects.length).sort((a, b) => b - a);

/** A fully-connected core with heavy internal edges. */
function core(prefix: string, n: number, weight: number): { nodes: string[]; edges: GraphEdgeLite[] } {
  const nodes = Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`);
  const edges: GraphEdgeLite[] = [];
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) edges.push(e(nodes[i], nodes[j], weight));
  return { nodes, edges };
}

/**
 * k dense communities, each internally complete, cross-linked by *several* light edges.
 *
 * Multiple cross-links matter: with a single link every join is a bridge, which the old
 * bridge-cutting implementation handled. Real orgs are not like that — poph-gaurav has 2078
 * edges over 202 objects and therefore almost no bridges, which is why bridge-cutting put
 * 165 of 169 objects in one cluster. This fixture reproduces that.
 */
function communities(k: number, size: number, crossLinks = 3): { nodes: string[]; edges: GraphEdgeLite[] } {
  const nodes: string[] = [];
  const edges: GraphEdgeLite[] = [];
  for (let c = 0; c < k; c++) {
    const { nodes: n, edges: es } = core(`D${c}_`, size, 10);
    nodes.push(...n);
    edges.push(...es);
    if (c > 0) {
      for (let l = 0; l < crossLinks; l++) {
        edges.push(e(`D${c - 1}_${(l % size) + 1}`, `D${c}_${(l % size) + 1}`, 1));
      }
    }
  }
  return { nodes, edges };
}

describe('clusterGraph', () => {
  describe('sparse graphs (forest — no community structure exists)', () => {
    it('keeps a uniform-weight hub and its spokes as one domain', () => {
      const spokes = ['Asset', 'Case', 'Contact', 'Contract', 'Opportunity', 'Order', 'Quote', 'Task'];
      const clusters = clusterGraph(['Account', ...spokes], spokes.map((s) => e('Account', s)), flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(9);
    });

    it('keeps a uniform-weight chain as one domain', () => {
      // Modularity shatters this into 11 adjacent pairs at every resolution — the density
      // gate is what stops that.
      const nodes = Array.from({ length: 22 }, (_, i) => `C${String(i).padStart(2, '0')}__c`);
      const clusters = clusterGraph(nodes, nodes.slice(0, -1).map((n, i) => e(n, nodes[i + 1])), flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(22);
    });

    it('keeps genuinely separate components separate', () => {
      const clusters = clusterGraph(['A1', 'A2', 'B1', 'B2'], [e('A1', 'A2'), e('B1', 'B2')], flat);

      expect(sizes(clusters)).toEqual([2, 2]);
    });

    it('handles an isolated node and an empty graph', () => {
      expect(clusterGraph(['Lonely__c'], [], flat)[0].objects).toEqual(['Lonely__c']);
      expect(clusterGraph([], [], flat)).toEqual([]);
    });
  });

  describe('dense graphs (modularity)', () => {
    it('separates dense communities joined by thin links', () => {
      const { nodes, edges } = communities(4, 5);

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters).toHaveLength(4);
      expect(sizes(clusters)).toEqual([5, 5, 5, 5]);
    });

    it('does not shear a lightly-coupled leaf off a dense core', () => {
      const c = core('A', 4, 10);
      const clusters = clusterGraph([...c.nodes, 'Leaf__c'], [...c.edges, e('A1', 'Leaf__c', 1)], flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(5);
    });

    it('keeps domains actionable on an org-scale graph', () => {
      // A 200-object graph of 10 real communities. Domains a consultant cannot act on are
      // as useless as one giant blob, so resolution is tuned to a target size.
      const { nodes, edges } = communities(10, 20);

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters.length).toBeGreaterThanOrEqual(10);
      expect(sizes(clusters)[0]).toBeLessThanOrEqual(25);
    });

    it('treats the target domain size as a ceiling, never inflating domains', () => {
      // The knob only tightens. If modularity already resolves finer than the target, that
      // stands; a smaller target must never hand back *larger* domains.
      const { nodes, edges } = communities(6, 30, 4);

      const loose = clusterGraph(nodes, edges, flat, { targetDomainSize: 40 });
      const tight = clusterGraph(nodes, edges, flat, { targetDomainSize: 10 });

      expect(sizes(tight)[0]).toBeLessThanOrEqual(sizes(loose)[0]);
      expect(tight.length).toBeGreaterThanOrEqual(loose.length);
    });
  });

  describe('output contract', () => {
    it('anchors each cluster on its highest-scoring object', () => {
      const nodes = ['Account', 'Case', 'Contact'];
      const edges = [e('Account', 'Case'), e('Case', 'Contact')];

      const clusters = clusterGraph(nodes, edges, (o) => (o === 'Case' ? 100 : 1));

      expect(clusters[0].anchorObject).toBe('Case');
    });

    it('is deterministic regardless of input order', () => {
      const { nodes, edges } = communities(5, 8);

      const a = clusterGraph(nodes, edges, flat);
      const b = clusterGraph([...nodes].reverse(), [...edges].reverse(), flat);

      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    });

    it('numbers clusters largest-first and partitions every node exactly once', () => {
      const { nodes, edges } = communities(3, 6);

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters.map((c) => c.id)).toEqual(['cluster-1', 'cluster-2', 'cluster-3']);
      const seen = clusters.flatMap((c) => c.objects);
      expect(seen.slice().sort()).toEqual([...nodes].sort());
      expect(new Set(seen).size).toBe(nodes.length);
    });
  });
});
