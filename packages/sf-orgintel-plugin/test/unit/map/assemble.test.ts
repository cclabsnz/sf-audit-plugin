import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseFlowXml } from '../../../src/map/flow/parseFlow.js';
import { assembleCouplingArtifacts } from '../../../src/map/assemble.js';
import type { NodeInfo } from '../../../src/map/graph/couplingGraph.js';
import type { ApexClassInput } from '../../../src/map/apex/apexTypes.js';

const DIR = join(process.cwd(), 'test/unit/map/fixtures/flows');
const flow = (f: string, api: string) => parseFlowXml(readFileSync(join(DIR, `${f}.flow-meta.xml`), 'utf8'), api);

const nodeInfo = (): NodeInfo => ({
  custom: false,
  automationCounts: { flows: 1, triggers: 1, approvals: 0 },
  recordCount90d: 100,
});

function assemble() {
  const classes: ApexClassInput[] = [
    {
      name: 'AcctContactSync',
      namespace: null,
      body: null,
      symbolTable: { externalReferences: [{ name: 'Account' }, { name: 'Contact' }] },
    },
  ];
  return assembleCouplingArtifacts({
    flowSummaries: [flow('Case_Router', 'Case_Router'), flow('New_Case_Screen', 'New_Case_Screen')],
    apexClasses: classes,
    apexTriggers: [],
    knownObjects: new Set(['Account', 'Case', 'WorkOrder', 'Contact']),
    nodeInfo,
    labelOf: (o) => o,
    topLayout: 20,
    couplingProvenance: {
      tool: 'orgintel',
      toolVersion: '0.1.0',
      generatedAt: '2026-07-26T00:00:00.000Z',
      orgId: '00Dxx',
      evidenceTier: 'B',
    },
    manifestProvenance: {
      tool: 'orgintel',
      toolVersion: '0.1.0',
      generatedAt: '2026-07-26T00:00:00.000Z',
      orgId: '00Dxx',
    },
  });
}

describe('assembleCouplingArtifacts', () => {
  const a = assemble();

  it('merges flow + apex edges into an aggregated coupling graph', () => {
    const g = a.couplingGraph;
    expect(g.version).toBe(1);
    expect(g.nodes.map((n) => n.object).sort()).toEqual(['Account', 'Case', 'Contact', 'WorkOrder']);

    // Case↔Account appears in both Case_Router and the screen flow -> weight 2.
    const caseAccount = g.edges.find((e) => e.from === 'Account' && e.to === 'Case');
    expect(caseAccount?.weight).toBe(2);
    expect(caseAccount?.operations).toContain('read');

    // Apex-derived Account↔Contact is high confidence.
    const acctContact = g.edges.find((e) => e.from === 'Account' && e.to === 'Contact');
    expect(acctContact?.components[0]).toMatchObject({ type: 'ApexClass', confidence: 'high' });
  });

  it('populates the landscape manifest L0/L1 and reserves L2-L4', () => {
    const m = a.manifest;
    expect(m.version).toBe(1);
    expect(m.levels.L0_landscape.clusters.length).toBeGreaterThan(0);
    expect(m.levels.L1_domain.perCluster[0].graphRef).toMatch(/^coupling-graph\.json#cluster-/);
    expect(m.levels.L2_process.perAnchor.every((p) => p.processGraphRef === null)).toBe(true);
    expect(m.levels.L3_transition.reserved).toBe(true);
    expect(m.levels.L4_component.flowSummaryRefs).toEqual([]);

    // Manifest node coords agree with the report layout.
    const anyCluster = m.levels.L1_domain.perCluster[0];
    for (const [obj, coord] of Object.entries(anyCluster.layout)) {
      expect(a.layout.get(obj)).toEqual(coord);
    }
  });

  it('is deterministic', () => {
    expect(assemble()).toEqual(a);
  });
});
