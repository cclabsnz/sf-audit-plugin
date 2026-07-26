import { describe, it, expect } from '@jest/globals';
import Ajv from 'ajv';
import { loadSchema } from '@cclabsnz/sf-core';
import type { CouplingGraph, LandscapeManifest, ProcessGraph } from '@cclabsnz/sf-core';

// strict:false + no ajv-formats: validate structure; the `date-time` format is treated as an
// annotation (we don't ship ajv-formats), which is fine for a structural contract test.
// Compile each schema once — Ajv rejects re-registering the same $id.
const ajv = new Ajv({ strict: false, allErrors: true });
const validators = {
  coupling: ajv.compile(loadSchema('coupling-graph') as object),
  manifest: ajv.compile(loadSchema('landscape-manifest') as object),
  process: ajv.compile(loadSchema('process-graph') as object),
};

const couplingGraph: CouplingGraph = {
  version: 1,
  provenance: {
    tool: 'orgintel',
    toolVersion: '0.1.0',
    generatedAt: '2026-07-26T00:00:00.000Z',
    orgId: '00Dxx',
    evidenceTier: 'B',
  },
  nodes: [{ object: 'Case', custom: false, automationCounts: { flows: 9, triggers: 2, approvals: 1 }, recordCount90d: 4120 }],
  edges: [
    {
      from: 'Case',
      to: 'WorkOrder',
      weight: 7,
      operations: ['create', 'update'],
      components: [{ type: 'Flow', name: 'Case_Router', confidence: 'high' }],
    },
  ],
};

const manifest: LandscapeManifest = {
  version: 1,
  provenance: { tool: 'orgintel', toolVersion: '0.1.0', generatedAt: '2026-07-26T00:00:00.000Z', orgId: '00Dxx' },
  levels: {
    L0_landscape: {
      clusters: [
        {
          id: 'cluster-1',
          label: 'Case',
          objects: ['Case', 'WorkOrder'],
          layout: { x: 120, y: 340 },
          metrics: { objects: 2, automations: 14, recordCount90d: 5200 },
        },
      ],
    },
    L1_domain: {
      perCluster: [
        {
          clusterId: 'cluster-1',
          graphRef: 'coupling-graph.json#cluster-1',
          anchorObject: 'Case',
          layout: { Case: { x: 100, y: 200 }, WorkOrder: { x: 300, y: 220 } },
        },
      ],
    },
    L2_process: { perAnchor: [{ anchorObject: 'Case', processGraphRef: null }] },
    L3_transition: { reserved: true },
    L4_component: { flowSummaryRefs: [] },
  },
};

const processGraph: ProcessGraph = {
  version: 1,
  anchorObject: 'Case',
  provenance: { tool: 'orgintel', toolVersion: '0.1.0', generatedAt: '2026-07-26T00:00:00.000Z', orgId: '00Dxx' },
  nodes: [{ id: 'n1', kind: 'state', label: 'New' }],
  edges: [{ from: 'n1', to: 'n1', trigger: 'manual' }],
};

describe('emitted IR validates against the core schemas', () => {
  it('coupling-graph.json', () => {
    expect(validators.coupling(couplingGraph)).toBe(true);
  });

  it('landscape-manifest.json', () => {
    const ok = validators.manifest(manifest);
    if (!ok) console.error(validators.manifest.errors);
    expect(ok).toBe(true);
  });

  it('process-graph.json (future contract is defined and valid)', () => {
    expect(validators.process(processGraph)).toBe(true);
  });

  it('rejects a coupling graph with the wrong version', () => {
    expect(validators.coupling({ ...couplingGraph, version: 2 })).toBe(false);
  });

  it('rejects an edge with an unknown operation', () => {
    const bad = { ...couplingGraph, edges: [{ ...couplingGraph.edges[0], operations: ['frobnicate'] }] };
    expect(validators.coupling(bad)).toBe(false);
  });
});
