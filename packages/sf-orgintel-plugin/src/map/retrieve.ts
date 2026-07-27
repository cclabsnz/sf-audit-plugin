import { ApexRepository, FlowRepository, describeSalesforceError, mapWithConcurrency } from '@cclabsnz/sf-core';
import type { IntelContext } from '../lib/wire.js';
import type { OrgIntelCache } from '../lib/cache.js';
import { contentHash } from '../lib/cache.js';
import type { FlowSummary } from './flow/flowTypes.js';
import type { ApexClassInput, ApexTriggerInput, SymbolTableLike } from './apex/apexTypes.js';
import { summarizeFlow } from './flow/parseFlow.js';
import type { XmlObject } from './flow/xml.js';
import type { ObjectResolver } from '../discover/objectResolver.js';

export interface RetrieveFlowOptions {
  includeInactive?: boolean;
}

/** Concurrent Tooling requests in flight while fetching flow metadata. */
const FLOW_CONCURRENCY = 8;

/**
 * Retrieve flow definitions and summarise each, via the core `FlowRepository` (which owns the
 * standard-vs-Tooling routing and the one-row-per-query rule for `Flow.Metadata`). Summaries
 * are cached per flow version id, so re-runs only re-analyse changed flows.
 */
export async function retrieveFlows(
  ctx: IntelContext,
  opts: RetrieveFlowOptions,
  notes: string[],
  cache?: OrgIntelCache,
): Promise<FlowSummary[]> {
  const flows = new FlowRepository(ctx.soql, ctx.tooling);

  let definitions;
  try {
    definitions = await flows.listDefinitions();
  } catch (e) {
    notes.push(`FlowDefinitionView is not queryable; flow coupling skipped. (${describeSalesforceError(e)})`);
    return [];
  }

  const { versions, managedSkipped } = FlowRepository.selectVersions(definitions, opts);
  if (managedSkipped > 0) {
    notes.push(`${managedSkipped} managed-package flow(s) skipped — metadata is not readable for managed flows.`);
  }

  // Serve cache hits first, then fetch only the misses. `Flow.Metadata` cannot be batched,
  // so bulk reads rely on bounded concurrency.
  const summaries: FlowSummary[] = [];
  const misses = versions.filter((v) => {
    const hit = cache?.get<FlowSummary>('flow', contentHash(v.id)) ?? null;
    if (hit) summaries.push(hit);
    return !hit;
  });

  await mapWithConcurrency(misses, FLOW_CONCURRENCY, async (v) => {
    let metadata: unknown;
    try {
      metadata = await flows.fetchMetadata(v.id);
    } catch (e) {
      notes.push(`Flow ${v.apiName} metadata was unavailable; skipped. (${describeSalesforceError(e)})`);
      return;
    }
    if (!metadata) {
      notes.push(`Flow ${v.apiName} returned no metadata; skipped.`);
      return;
    }
    try {
      const summary = summarizeFlow(metadata as XmlObject, v.apiName);
      summaries.push(summary);
      cache?.set('flow', contentHash(v.id), summary);
    } catch (e) {
      notes.push(`Flow ${v.apiName} could not be parsed; skipped. (${describeSalesforceError(e)})`);
    }
  });

  // Deterministic regardless of cache-hit and completion ordering.
  notes.sort();
  return summaries.sort((a, b) => a.apiName.localeCompare(b.apiName));
}

/**
 * Retrieve Apex classes and triggers via the core `ApexRepository`, which knows that only
 * `ApexClass` carries a `SymbolTable` column. Triggers fall back to body analysis.
 */
export async function retrieveApex(
  ctx: IntelContext,
  resolver: ObjectResolver,
  notes: string[],
): Promise<{ classes: ApexClassInput[]; triggers: ApexTriggerInput[] }> {
  const apex = new ApexRepository(ctx.tooling);
  let classes: ApexClassInput[] = [];
  let triggers: ApexTriggerInput[] = [];

  try {
    classes = (await apex.listClasses()).map((c) => ({
      name: c.name,
      namespace: c.namespace,
      body: c.body,
      symbolTable: (c.symbolTable as SymbolTableLike | null) ?? null,
    }));
  } catch (e) {
    notes.push(`ApexClass is not queryable; class coupling skipped. (${describeSalesforceError(e)})`);
  }

  try {
    triggers = (await apex.listTriggers())
      .map((t) => ({
        name: t.name,
        namespace: t.namespace,
        object: resolver.resolve(t.tableEnumOrId) ?? t.tableEnumOrId,
        body: t.body,
        symbolTable: null,
      }))
      .filter((t) => !!t.object);
  } catch (e) {
    notes.push(`ApexTrigger is not queryable; trigger coupling skipped. (${describeSalesforceError(e)})`);
  }

  return { classes, triggers };
}
