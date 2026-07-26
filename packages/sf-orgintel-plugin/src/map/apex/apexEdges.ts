import type { CouplingOperation, RawEdge, ComponentRef } from '../types.js';
import type { ApexClassInput, ApexTriggerInput, ApexAnalysis, SymbolTableLike } from './apexTypes.js';
import { regexAnalyze } from './apexRegex.js';

/** Object references from a compiled class's SymbolTable (external references ∩ known objects). */
export function symbolTableObjects(st: SymbolTableLike | null, known: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const ref of st?.externalReferences ?? []) {
    if (ref?.name && known.has(ref.name)) out.add(ref.name);
  }
  return out;
}

/**
 * Analyse one Apex body+SymbolTable. SymbolTable object references (compiled) are high
 * confidence; if none are available (uncompiled/empty), fall back to body regex (approximate).
 * Operations come from the body regex in both cases (SymbolTable doesn't carry them cleanly).
 */
export function analyzeApex(
  input: { body: string | null; symbolTable: SymbolTableLike | null },
  known: Set<string>,
): ApexAnalysis {
  const regex = input.body ? regexAnalyze(input.body, known) : new Map<string, Set<CouplingOperation>>();
  const stObjects = symbolTableObjects(input.symbolTable, known);

  if (stObjects.size > 0) {
    const objects = new Map<string, Set<CouplingOperation>>();
    for (const o of stObjects) objects.set(o, regex.get(o) ?? new Set<CouplingOperation>(['read']));
    return { objects, confidence: 'high' };
  }
  return { objects: regex, confidence: 'approximate' };
}

export function deriveApexEdges(
  classes: ApexClassInput[],
  triggers: ApexTriggerInput[],
  known: Set<string>,
): RawEdge[] {
  const edges: RawEdge[] = [];

  // Classes couple their referenced objects pairwise.
  for (const cls of classes) {
    const { objects, confidence } = analyzeApex(cls, known);
    const component: ComponentRef = { type: 'ApexClass', name: cls.name, confidence, namespace: cls.namespace };
    const objs = [...objects.keys()].sort();
    for (let i = 0; i < objs.length; i++) {
      for (let j = i + 1; j < objs.length; j++) {
        const ops = new Set<CouplingOperation>([...objects.get(objs[i])!, ...objects.get(objs[j])!]);
        edges.push({ a: objs[i], b: objs[j], operations: [...ops].sort(), component });
      }
    }
  }

  // Triggers: source object -> each body-derived target object.
  for (const trig of triggers) {
    const { objects, confidence } = analyzeApex(trig, known);
    const component: ComponentRef = { type: 'ApexTrigger', name: trig.name, confidence, namespace: trig.namespace };
    for (const [obj, ops] of objects) {
      if (obj === trig.object) continue;
      edges.push({ a: trig.object, b: obj, operations: [...ops].sort(), component });
    }
  }

  return edges;
}
