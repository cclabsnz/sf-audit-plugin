import { describe, it, expect } from '@jest/globals';
import { clusterGraph, type GraphEdgeLite } from '../../../src/map/graph/clusters.js';

/**
 * Domain clustering must survive the topologies real Salesforce orgs actually have.
 *
 * The rule under test: a bridge is cut only when it is weak *relative to* the domains it
 * joins — not merely the lightest edge in the graph. In a tree every edge is a bridge, so an
 * absolute "cut the minimum-weight bridge" rule shatters uniform-weight graphs into singletons.
 */

const e = (from: string, to: string, weight = 1): GraphEdgeLite => ({ from, to, weight });

/** Uniform score — anchor selection falls back to alphabetical order. */
const flat = (): number => 1;

const sizes = (clusters: Array<{ objects: string[] }>): number[] =>
  clusters.map((c) => c.objects.length).sort((a, b) => b - a);

/** A fully-connected core with heavy internal edges. */
function core(prefix: string, n: number, weight: number): { nodes: string[]; edges: GraphEdgeLite[] } {
  const nodes = Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`);
  const edges: GraphEdgeLite[] = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) edges.push(e(nodes[i], nodes[j], weight));
  }
  return { nodes, edges };
}

describe('clusterGraph', () => {
  describe('does not shatter tree topologies', () => {
    it('keeps a uniform-weight hub and its spokes as one domain', () => {
      // The canonical Salesforce shape: Account at the centre, everything hanging off it.
      const spokes = ['Asset', 'Case', 'Contact', 'Contract', 'Opportunity', 'Order', 'Quote', 'Task'];
      const nodes = ['Account', ...spokes];
      const edges = spokes.map((s) => e('Account', s));

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(9);
      expect(clusters[0].objects).toContain('Account');
    });

    it('keeps a uniform-weight chain as one domain', () => {
      // Lead -> Opportunity -> Order -> Invoice style hand-offs.
      const nodes = ['Lead', 'Opportunity', 'Order', 'Invoice__c', 'Payment__c', 'Receipt__c'];
      const edges = nodes.slice(0, -1).map((n, i) => e(n, nodes[i + 1]));

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(6);
    });

    it('does not shear a lightly-coupled leaf off a dense core', () => {
      // Cutting here would invent a one-object "domain", which is never a useful answer.
      const c = core('A', 3, 10);
      const nodes = [...c.nodes, 'Leaf__c'];
      const edges = [...c.edges, e('A1', 'Leaf__c', 1)];

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(4);
    });

    it('keeps genuinely separate components separate', () => {
      const nodes = ['A1', 'A2', 'B1', 'B2'];
      const edges = [e('A1', 'A2'), e('B1', 'B2')];

      const clusters = clusterGraph(nodes, edges, flat);

      expect(sizes(clusters)).toEqual([2, 2]);
    });

    it('handles an isolated node with no edges', () => {
      const clusters = clusterGraph(['Lonely__c'], [], flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toEqual(['Lonely__c']);
    });

    it('handles an empty graph', () => {
      expect(clusterGraph([], [], flat)).toEqual([]);
    });
  });

  describe('still splits genuinely weak bridges', () => {
    it('splits two dense cores joined by one thin edge', () => {
      // The case the bridge-cutting exists for: a tenuous link must not fuse two real domains.
      const a = core('A', 3, 10);
      const b = core('B', 3, 10);
      const nodes = [...a.nodes, ...b.nodes];
      const edges = [...a.edges, ...b.edges, e('A1', 'B1', 1)];

      const clusters = clusterGraph(nodes, edges, flat);

      expect(sizes(clusters)).toEqual([3, 3]);
      const withA1 = clusters.find((c) => c.objects.includes('A1'))!;
      expect(withA1.objects).toEqual(['A1', 'A2', 'A3']);
    });

    it('does not split cores joined by a proportionally strong edge', () => {
      // Same shape, but the connecting edge is comparable to the internal ones — one domain.
      const a = core('A', 3, 10);
      const b = core('B', 3, 10);
      const nodes = [...a.nodes, ...b.nodes];
      const edges = [...a.edges, ...b.edges, e('A1', 'B1', 9)];

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters).toHaveLength(1);
      expect(clusters[0].objects).toHaveLength(6);
    });
  });

  describe('output contract', () => {
    it('anchors each cluster on its highest-scoring object', () => {
      const nodes = ['Account', 'Case', 'Contact'];
      const edges = [e('Account', 'Case'), e('Case', 'Contact')];
      const score = (o: string): number => (o === 'Case' ? 100 : 1);

      const clusters = clusterGraph(nodes, edges, score);

      expect(clusters[0].anchorObject).toBe('Case');
    });

    it('is deterministic across repeated runs', () => {
      const a = core('A', 3, 10);
      const b = core('B', 3, 10);
      const nodes = [...a.nodes, ...b.nodes];
      const edges = [...a.edges, ...b.edges, e('A1', 'B1', 1)];

      const first = clusterGraph(nodes, edges, flat);
      const second = clusterGraph(nodes, edges, flat);

      expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    });

    it('numbers clusters largest-first', () => {
      const a = core('A', 4, 10);
      const nodes = [...a.nodes, 'B1', 'B2'];
      const edges = [...a.edges, e('B1', 'B2')];

      const clusters = clusterGraph(nodes, edges, flat);

      expect(clusters.map((c) => c.id)).toEqual(['cluster-1', 'cluster-2']);
      expect(clusters[0].objects).toHaveLength(4);
    });
  });
});
