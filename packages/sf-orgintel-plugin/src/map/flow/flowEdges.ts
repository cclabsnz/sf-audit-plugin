import type { FlowSummary, FlowOperation } from './flowTypes.js';
import type { RawEdge, ComponentRef, CouplingOperation } from '../types.js';

export interface FlowEdgeResult {
  edges: RawEdge[];
  /** Subflow apiNames referenced but not retrieved (managed/absent) — reported, not fatal. */
  missingSubflows: string[];
}

/**
 * Derive coupling edges from all flows. Each flow's effective touched objects include those
 * of its subflows (resolved recursively, cycle-safe). Record-triggered flows emit edges from
 * the trigger object to each touched object; flows without a trigger object couple their
 * touched objects pairwise (screen = human-initiated, autolaunched = invocable).
 */
export function deriveFlowEdges(summaries: FlowSummary[]): FlowEdgeResult {
  const byName = new Map(summaries.map((s) => [s.apiName, s]));
  const edges: RawEdge[] = [];
  const missing = new Set<string>();

  for (const flow of summaries) {
    const touches = resolveTouches(flow, byName, new Set(), missing);
    const component: ComponentRef = {
      type: 'Flow',
      name: flow.apiName,
      confidence: 'high',
      namespace: flow.namespace,
    };
    edges.push(...edgesForFlow(flow, touches, component));
  }

  // A subflow "missing" only if it was never retrieved as a top-level summary.
  const known = new Set(summaries.map((s) => s.apiName));
  return { edges, missingSubflows: [...missing].filter((m) => !known.has(m)).sort() };
}

/** object -> set of operations, unioned across the flow and its subflows. */
type TouchMap = Map<string, Set<CouplingOperation>>;

function resolveTouches(
  flow: FlowSummary,
  byName: Map<string, FlowSummary>,
  visited: Set<string>,
  missing: Set<string>,
): TouchMap {
  const map: TouchMap = new Map();
  if (visited.has(flow.apiName)) return map; // cycle guard
  visited.add(flow.apiName);

  add(map, flow.recordLookups, 'read');
  add(map, flow.recordCreates, 'create');
  add(map, flow.recordUpdates, 'update');
  add(map, flow.recordDeletes, 'delete');

  for (const sub of flow.subflows) {
    const child = byName.get(sub);
    if (!child) {
      missing.add(sub);
      continue;
    }
    for (const [obj, ops] of resolveTouches(child, byName, visited, missing)) {
      for (const op of ops) upsert(map, obj, op);
    }
  }
  return map;
}

function edgesForFlow(flow: FlowSummary, touches: TouchMap, component: ComponentRef): RawEdge[] {
  const trigger = flow.start.triggerObject;
  const edges: RawEdge[] = [];

  if (trigger) {
    for (const [obj, ops] of touches) {
      if (obj === trigger) continue;
      edges.push({ a: trigger, b: obj, operations: [...ops].sort(), component });
    }
    return edges;
  }

  // No trigger object: couple touched objects pairwise (co-occurrence in one flow).
  const objects = [...touches.keys()].sort();
  for (let i = 0; i < objects.length; i++) {
    for (let j = i + 1; j < objects.length; j++) {
      const ops = new Set<CouplingOperation>([...touches.get(objects[i])!, ...touches.get(objects[j])!]);
      edges.push({ a: objects[i], b: objects[j], operations: [...ops].sort(), component });
    }
  }
  return edges;
}

function add(map: TouchMap, refs: { object: string }[], op: FlowOperation): void {
  for (const r of refs) upsert(map, r.object, op);
}

function upsert(map: TouchMap, obj: string, op: CouplingOperation): void {
  const set = map.get(obj) ?? new Set<CouplingOperation>();
  set.add(op);
  map.set(obj, set);
}
