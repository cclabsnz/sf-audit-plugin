import { FlowRepository } from '@cclabsnz/sf-core';
import type { SoqlClient, ToolingClient } from '@cclabsnz/sf-core';
import type { AutomationCounts } from './types.js';
import type { ObjectResolver } from './objectResolver.js';
import type { SObjectCatalog } from '../probe/sobjectCatalog.js';

/**
 * Per-object automation counts. Triggers/approvals/workflow rules are resolved to their
 * object API name (exact). Record-triggered flows are matched by trigger-object label
 * against the catalog (approximate — the Flow XML parser in `intel map` is authoritative).
 */
export interface AutomationIndex {
  countsFor(object: string): AutomationCounts;
  /** Objects that have any automation — used to prioritise which objects to deep-probe. */
  automatedObjects(): Set<string>;
  notes: string[];
}

interface ApexTriggerRow {
  TableEnumOrId: string;
  Status?: string;
}
interface WorkflowRuleRow {
  TableEnumOrId: string;
}
interface ProcessDefinitionRow {
  TableEnumOrId: string;
  Type: string;
  State?: string;
}
const RECORD_TRIGGER_TYPES = new Set(['RecordAfterSave', 'RecordBeforeSave']);

export async function buildAutomationIndex(
  soql: SoqlClient,
  tooling: ToolingClient,
  resolver: ObjectResolver,
  catalog: SObjectCatalog,
): Promise<AutomationIndex> {
  const triggers = new Map<string, number>();
  const workflows = new Map<string, number>();
  const approvals = new Map<string, number>();
  const flows = new Map<string, number>();
  const notes: string[] = [];

  // Apex triggers (active) — Tooling
  await safe(notes, 'Apex triggers', async () => {
    const rows = await tooling.query<ApexTriggerRow>('SELECT TableEnumOrId, Status FROM ApexTrigger');
    for (const r of rows) {
      if (r.Status && r.Status !== 'Active') continue;
      bump(triggers, resolver.resolve(r.TableEnumOrId));
    }
  });

  // Workflow rules — Tooling
  await safe(notes, 'Workflow rules', async () => {
    const rows = await tooling.query<WorkflowRuleRow>('SELECT TableEnumOrId FROM WorkflowRule');
    for (const r of rows) bump(workflows, resolver.resolve(r.TableEnumOrId));
  });

  // Approval processes — ProcessDefinition (SOQL)
  await safe(notes, 'Approval processes', async () => {
    const result = await soql.queryAll<ProcessDefinitionRow>(
      "SELECT TableEnumOrId, Type, State FROM ProcessDefinition WHERE Type = 'Approval'",
    );
    for (const r of result) {
      if (r.State && r.State !== 'Active') continue;
      bump(approvals, resolver.resolve(r.TableEnumOrId));
    }
  });

  // Record-triggered flows — routed through the core FlowRepository, which owns the fact
  // that FlowDefinitionView is a standard object and not a Tooling one.
  await safe(notes, 'Record-triggered flows', async () => {
    const labelToApi = buildLabelIndex(catalog);
    const rows = await new FlowRepository(soql, tooling).listTriggerViews();
    for (const r of rows) {
      if (!r.isActive) continue;
      if (!r.triggerType || !RECORD_TRIGGER_TYPES.has(r.triggerType)) continue;
      const api = r.triggerObjectOrEventLabel ? labelToApi.get(r.triggerObjectOrEventLabel.toLowerCase()) : undefined;
      if (api) bump(flows, api);
    }
    notes.push('Flow trigger-object matched by label (approximate); `intel map` resolves flows exactly.');
  });

  const automatedObjects = new Set<string>([
    ...triggers.keys(),
    ...workflows.keys(),
    ...approvals.keys(),
    ...flows.keys(),
  ]);

  return {
    countsFor(object: string): AutomationCounts {
      const t = triggers.get(object) ?? 0;
      const w = workflows.get(object) ?? 0;
      const a = approvals.get(object) ?? 0;
      const f = flows.get(object) ?? 0;
      return { flows: f, triggers: t, approvals: a, workflowRules: w, total: t + w + a + f };
    },
    automatedObjects: () => automatedObjects,
    notes,
  };
}

function bump(map: Map<string, number>, key: string | null): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

function buildLabelIndex(catalog: SObjectCatalog): Map<string, string> {
  const idx = new Map<string, string>();
  for (const s of catalog.all()) idx.set(s.label.toLowerCase(), s.name);
  return idx;
}

async function safe(notes: string[], what: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch {
    notes.push(`${what} could not be queried; counted as 0.`);
  }
}
