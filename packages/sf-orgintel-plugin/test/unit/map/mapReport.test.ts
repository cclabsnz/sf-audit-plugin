import { describe, it, expect } from '@jest/globals';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import type { CouplingGraph } from '@cclabsnz/sf-core';
import { renderMapHtml } from '../../../src/report/mapReport.js';
import type { Cluster } from '../../../src/map/graph/clusters.js';
import type { Point } from '../../../src/map/graph/layout.js';

const graph: CouplingGraph = {
  version: 1,
  provenance: { tool: 'orgintel', toolVersion: '0.1.0', generatedAt: '2026-07-26T00:00:00.000Z', orgId: '00D', evidenceTier: 'B' },
  nodes: [
    { object: 'Case', custom: false, automationCounts: { flows: 3, triggers: 1, approvals: 0 }, recordCount90d: 100 },
    { object: 'WorkOrder', custom: false, automationCounts: { flows: 1, triggers: 0, approvals: 0 }, recordCount90d: 50 },
  ],
  edges: [
    { from: 'Case', to: 'WorkOrder', weight: 4, operations: ['create', 'update'], components: [{ type: 'Flow', name: 'Case_Router', confidence: 'high' }] },
  ],
};
const clusters: Cluster[] = [{ id: 'cluster-1', objects: ['Case', 'WorkOrder'], anchorObject: 'Case' }];
const layout = new Map<string, Point>([
  ['Case', { x: 200, y: 300 }],
  ['WorkOrder', { x: 500, y: 320 }],
]);

describe('renderMapHtml', () => {
  it('renders a self-contained report with an SVG graph and the coupling table', () => {
    const html = renderMapHtml({
      orgName: 'Acme',
      couplingGraph: graph,
      clusters,
      layout,
      evidenceTier: 'B',
      flowsAnalyzed: 5,
      apexClassesAnalyzed: 3,
      apexTriggersAnalyzed: 2,
      generatedAt: graph.provenance.generatedAt,
      branding: DEFAULT_BRANDING,
    });
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('Cross-Object Coupling Map');
    expect(html).toContain('<svg');
    expect(html).toContain('Case ↔ WorkOrder');
    expect(html).toContain('Process backbones');
    // No cached discover -> anchors note
    expect(html).toContain('Run <code>sf intel discover</code>');
  });

  it('shows anchors when cached discover results are supplied', () => {
    const html = renderMapHtml({
      orgName: 'Acme',
      couplingGraph: graph,
      clusters,
      layout,
      anchors: [{ object: 'Case', label: 'Case', score: 0.91 }],
      evidenceTier: 'B',
      flowsAnalyzed: 5,
      apexClassesAnalyzed: 3,
      apexTriggersAnalyzed: 2,
      generatedAt: graph.provenance.generatedAt,
      branding: DEFAULT_BRANDING,
    });
    expect(html).toContain('from cached discover');
    expect(html).toContain('0.910');
  });
});
