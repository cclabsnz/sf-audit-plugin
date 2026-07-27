import { describe, it, expect } from '@jest/globals';
import { assembleCouplingArtifacts } from '../../../src/map/assemble.js';
import type { FlowSummary } from '../../../src/map/flow/flowTypes.js';

/**
 * The landscape manifest is a navigation contract for a viewer: L0 positions each domain in
 * the landscape, L1 positions the objects inside a domain. A viewer can only zoom to what has
 * coordinates, so both levels must be *complete* — independent of how many nodes the HTML
 * report chooses to draw in its top-N picture.
 */

function flow(apiName: string, trigger: string, updates: string[]): FlowSummary {
  return {
    apiName,
    label: apiName,
    apiVersion: '62.0',
    processType: 'AutoLaunchedFlow',
    status: 'Active',
    namespace: null,
    start: { triggerType: 'RecordAfterSave', triggerObject: trigger, recordTriggerType: 'CreateAndUpdate' },
    initiator: 'record-trigger',
    recordLookups: [],
    recordCreates: [],
    recordUpdates: updates.map((o, i) => ({ name: `u${i}`, object: o })),
    recordDeletes: [],
    actionCalls: [],
    subflows: [],
    screenCount: 0,
    decisionCount: 0,
    loopCount: 0,
  };
}

const PROVENANCE = { tool: 'orgintel' as const, toolVersion: '0.1.0', generatedAt: '2026-07-27T00:00:00.000Z', orgId: '00Dxx' };

/**
 * A 22-object chain plus a separate 2-object domain. The small domain has no member in the
 * default top-20 layout, which is exactly the case that used to collapse it to the origin.
 */
function bigAndSmallDomains() {
  const chain = Array.from({ length: 22 }, (_, i) => `Chain${String(i).padStart(2, '0')}__c`);
  const flows = chain.slice(0, -1).map((o, i) => flow(`ChainFlow${i}`, o, [chain[i + 1]]));
  flows.push(flow('TinyFlow', 'Tiny_A__c', ['Tiny_B__c']));
  const objects = [...chain, 'Tiny_A__c', 'Tiny_B__c'];

  return assembleCouplingArtifacts({
    flowSummaries: flows,
    apexClasses: [],
    apexTriggers: [],
    knownObjects: new Set(objects),
    nodeInfo: () => ({ custom: true, automationCounts: { flows: 1, triggers: 0, approvals: 0 }, recordCount90d: 10 }),
    labelOf: (o) => o,
    couplingProvenance: { ...PROVENANCE, evidenceTier: 'B' as const },
    manifestProvenance: PROVENANCE,
  });
}

describe('landscape manifest layout', () => {
  it('gives every object in every cluster an L1 coordinate', () => {
    const { manifest, clusters } = bigAndSmallDomains();

    for (const cluster of clusters) {
      const level1 = manifest.levels.L1_domain.perCluster.find((p) => p.clusterId === cluster.id);
      expect(level1).toBeDefined();
      const covered = Object.keys(level1!.layout).sort();
      expect(covered).toEqual([...cluster.objects].sort());
    }
  });

  it('gives every cluster a distinct L0 position', () => {
    const { manifest, clusters } = bigAndSmallDomains();
    expect(clusters.length).toBeGreaterThan(1);

    const positions = manifest.levels.L0_landscape.clusters.map((c) => `${c.layout.x},${c.layout.y}`);
    expect(new Set(positions).size).toBe(positions.length);
  });

  it('never collapses a cluster to the origin', () => {
    // {0,0} was the sentinel a missing layout produced — small domains stacked there.
    const { manifest } = bigAndSmallDomains();

    const atOrigin = manifest.levels.L0_landscape.clusters.filter((c) => c.layout.x === 0 && c.layout.y === 0);
    expect(atOrigin).toEqual([]);
  });

  it('lays out a domain independently of the report top-N cutoff', () => {
    // topLayout only governs the report picture; the manifest must be complete regardless.
    const chain = Array.from({ length: 22 }, (_, i) => `Chain${String(i).padStart(2, '0')}__c`);
    const flows = chain.slice(0, -1).map((o, i) => flow(`ChainFlow${i}`, o, [chain[i + 1]]));

    const artifacts = assembleCouplingArtifacts({
      flowSummaries: flows,
      apexClasses: [],
      apexTriggers: [],
      knownObjects: new Set(chain),
      nodeInfo: () => ({ custom: true, automationCounts: { flows: 1, triggers: 0, approvals: 0 }, recordCount90d: 10 }),
      labelOf: (o) => o,
      couplingProvenance: { ...PROVENANCE, evidenceTier: 'B' as const },
      manifestProvenance: PROVENANCE,
      topLayout: 5,
    });

    expect(artifacts.layout.size).toBe(5); // report picture stays capped
    const level1 = artifacts.manifest.levels.L1_domain.perCluster[0];
    expect(Object.keys(level1.layout)).toHaveLength(22); // manifest stays complete
  });

  it('preserves cluster metrics', () => {
    const { manifest, clusters } = bigAndSmallDomains();

    const l0 = manifest.levels.L0_landscape.clusters.find((c) => c.objects.length === 2)!;
    const cluster = clusters.find((c) => c.objects.length === 2)!;
    expect(l0.id).toBe(cluster.id);
    expect(l0.metrics.objects).toBe(2);
    expect(l0.metrics.automations).toBe(2); // one flow per node in nodeInfo
    expect(l0.metrics.recordCount90d).toBe(20);
  });

  it('is deterministic across repeated runs', () => {
    const first = bigAndSmallDomains().manifest;
    const second = bigAndSmallDomains().manifest;

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});
