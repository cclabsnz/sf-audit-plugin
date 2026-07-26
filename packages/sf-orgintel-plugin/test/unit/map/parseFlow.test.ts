import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseFlowXml } from '../../../src/map/flow/parseFlow.js';
import { deriveFlowEdges } from '../../../src/map/flow/flowEdges.js';
import type { FlowSummary } from '../../../src/map/flow/flowTypes.js';
import type { RawEdge } from '../../../src/map/types.js';

const DIR = join(process.cwd(), 'test/unit/map/fixtures/flows');
const load = (file: string, apiName: string): FlowSummary =>
  parseFlowXml(readFileSync(join(DIR, `${file}.flow-meta.xml`), 'utf8'), apiName);

const edge = (edges: RawEdge[], x: string, y: string): RawEdge | undefined =>
  edges.find((e) => (e.a === x && e.b === y) || (e.a === y && e.b === x));

describe('parseFlowXml — FlowSummary snapshots', () => {
  it('record-triggered cross-object flow', () => {
    const s = load('Case_Router', 'Case_Router');
    expect(s).toMatchObject({
      label: 'Case Router',
      processType: 'AutoLaunchedFlow',
      status: 'Active',
      apiVersion: '62.0',
      namespace: null,
      initiator: 'record-trigger',
      start: { triggerType: 'RecordAfterSave', triggerObject: 'Case', recordTriggerType: 'CreateAndUpdate' },
      actionCalls: ['CaseRoutingService'],
      decisionCount: 1,
      screenCount: 0,
    });
    expect(s.recordLookups.map((r) => r.object)).toEqual(['Account']);
    expect(s.recordCreates.map((r) => r.object)).toEqual(['WorkOrder']);
    expect(s.recordUpdates.map((r) => r.object)).toEqual(['Case', 'WorkOrder']);
  });

  it('screen flow is human-initiated with no trigger object', () => {
    const s = load('New_Case_Screen', 'New_Case_Screen');
    expect(s.processType).toBe('Flow');
    expect(s.initiator).toBe('human');
    expect(s.start.triggerObject).toBeNull();
    expect(s.screenCount).toBe(2);
    expect(s.recordCreates.map((r) => r.object)).toEqual(['Case']);
  });

  it('loops/decisions-only flow touches no objects and is invocable', () => {
    const s = load('Loops_Only_Flow', 'Loops_Only_Flow');
    expect(s.loopCount).toBe(2);
    expect(s.decisionCount).toBe(1);
    expect(s.initiator).toBe('invocable');
    expect(s.recordLookups.concat(s.recordCreates, s.recordUpdates, s.recordDeletes)).toEqual([]);
  });

  it('managed-namespace flow carries its namespace', () => {
    const s = load('acme__Managed_Sync', 'acme__Managed_Sync');
    expect(s.namespace).toBe('acme');
    expect(s.start.triggerObject).toBe('Account');
    expect(s.recordCreates.map((r) => r.object)).toEqual(['acme__Widget__c']);
  });
});

describe('deriveFlowEdges — edge snapshots', () => {
  it('record-triggered flow: trigger -> each touched object with operations', () => {
    const { edges } = deriveFlowEdges([load('Case_Router', 'Case_Router')]);
    expect(edge(edges, 'Case', 'Account')?.operations).toEqual(['read']);
    expect(edge(edges, 'Case', 'WorkOrder')?.operations).toEqual(['create', 'update']);
    // self-edge (Case updates Case) is not emitted
    expect(edge(edges, 'Case', 'Case')).toBeUndefined();
    expect(edges).toHaveLength(2);
    expect(edges[0].component).toMatchObject({ type: 'Flow', name: 'Case_Router', confidence: 'high' });
  });

  it('screen flow couples touched objects pairwise', () => {
    const { edges } = deriveFlowEdges([load('New_Case_Screen', 'New_Case_Screen')]);
    expect(edges).toHaveLength(1);
    expect(edge(edges, 'Account', 'Case')?.operations).toEqual(['create', 'read']);
  });

  it('subflow chain: parent inherits child touched objects (cycle-safe)', () => {
    const parent = load('Parent_Order_Flow', 'Parent_Order_Flow');
    const child = load('Child_Fulfillment_Flow', 'Child_Fulfillment_Flow');
    const { edges, missingSubflows } = deriveFlowEdges([parent, child]);
    // Parent trigger Order reaches Shipment__c (created inside the subflow)
    expect(edge(edges, 'Order', 'Shipment__c')?.operations).toEqual(['create']);
    expect(missingSubflows).toEqual([]);
  });

  it('reports subflows that were not retrieved', () => {
    const { missingSubflows } = deriveFlowEdges([load('Parent_Order_Flow', 'Parent_Order_Flow')]);
    expect(missingSubflows).toEqual(['Child_Fulfillment_Flow']);
  });

  it('loops-only flow yields no edges', () => {
    const { edges } = deriveFlowEdges([load('Loops_Only_Flow', 'Loops_Only_Flow')]);
    expect(edges).toEqual([]);
  });
});
