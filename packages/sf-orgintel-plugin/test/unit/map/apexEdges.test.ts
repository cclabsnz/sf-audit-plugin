import { describe, it, expect } from '@jest/globals';
import { deriveApexEdges, analyzeApex } from '../../../src/map/apex/apexEdges.js';
import type { ApexClassInput, ApexTriggerInput } from '../../../src/map/apex/apexTypes.js';
import type { RawEdge } from '../../../src/map/types.js';

const known = new Set(['Account', 'Case', 'Contact', 'WorkOrder']);
const edge = (edges: RawEdge[], x: string, y: string): RawEdge | undefined =>
  edges.find((e) => (e.a === x && e.b === y) || (e.a === y && e.b === x));

describe('analyzeApex', () => {
  it('uses SymbolTable external references (high confidence)', () => {
    const a = analyzeApex(
      { body: null, symbolTable: { externalReferences: [{ name: 'Account' }, { name: 'Case' }, { name: 'String' }] } },
      known,
    );
    expect(a.confidence).toBe('high');
    expect([...a.objects.keys()].sort()).toEqual(['Account', 'Case']); // String is not a known object
  });

  it('falls back to body regex when SymbolTable is empty (approximate)', () => {
    const body = 'Account a = new Account(); insert a; List<Case> cs = [SELECT Id FROM Case]; update cs;';
    const a = analyzeApex({ body, symbolTable: null }, known);
    expect(a.confidence).toBe('approximate');
    expect([...a.objects.get('Account')!].sort()).toEqual(['create']);
    expect([...a.objects.get('Case')!].sort()).toEqual(['read', 'update']);
  });
});

describe('deriveApexEdges', () => {
  it('couples a class\'s referenced objects pairwise via regex fallback', () => {
    const classes: ApexClassInput[] = [
      {
        name: 'CaseRoutingService',
        namespace: null,
        symbolTable: null,
        body: 'Account a = [SELECT Id FROM Account]; Case c = new Case(); insert c;',
      },
    ];
    const edges = deriveApexEdges(classes, [], known);
    const e = edge(edges, 'Account', 'Case');
    expect(e).toBeDefined();
    expect(e!.operations).toEqual(['create', 'read']);
    expect(e!.component).toMatchObject({ type: 'ApexClass', name: 'CaseRoutingService', confidence: 'approximate' });
  });

  it('emits trigger edges from the source object with SymbolTable confidence', () => {
    const triggers: ApexTriggerInput[] = [
      {
        name: 'CaseTrigger',
        namespace: null,
        object: 'Case',
        symbolTable: { externalReferences: [{ name: 'WorkOrder' }] },
        body: 'WorkOrder w = new WorkOrder(); insert w;',
      },
    ];
    const edges = deriveApexEdges([], triggers, known);
    const e = edge(edges, 'Case', 'WorkOrder');
    expect(e).toBeDefined();
    expect(e!.operations).toEqual(['create']);
    expect(e!.component).toMatchObject({ type: 'ApexTrigger', name: 'CaseTrigger', confidence: 'high' });
  });

  it('does not emit a self-edge when a trigger touches its own object', () => {
    const triggers: ApexTriggerInput[] = [
      { name: 'AccountTrigger', namespace: null, object: 'Account', symbolTable: null, body: 'Account a; update a;' },
    ];
    // 'Account a;' declares the var; 'update a' -> Account update, but source==target so skipped
    const edges = deriveApexEdges([], triggers, known);
    expect(edge(edges, 'Account', 'Account')).toBeUndefined();
  });
});
