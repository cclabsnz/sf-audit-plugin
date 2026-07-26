import type { ToolingClient } from '@cclabsnz/sf-core';
import type { IntelContext } from '../lib/wire.js';
import type { OrgIntelCache } from '../lib/cache.js';
import type { FlowSummary } from './flow/flowTypes.js';
import type { ApexClassInput, ApexTriggerInput, SymbolTableLike } from './apex/apexTypes.js';
import { summarizeFlow } from './flow/parseFlow.js';
import type { XmlObject } from './flow/xml.js';
import type { ObjectResolver } from '../discover/objectResolver.js';

export interface RetrieveFlowOptions {
  includeInactive?: boolean;
}

interface FlowDefView {
  ApiName: string;
  IsActive: boolean;
  ActiveVersionId: string | null;
  LatestVersionId?: string | null;
}

/**
 * Retrieve flow definitions and summarise each. Uses the Tooling `Flow.Metadata` structured
 * field (equivalent to the flow's XML) fed through the same `summarizeFlow` core the XML
 * parser uses. Cached per flow version, so re-runs only re-analyse changed flows.
 */
export async function retrieveFlows(
  ctx: IntelContext,
  opts: RetrieveFlowOptions,
  notes: string[],
  cache?: OrgIntelCache,
): Promise<FlowSummary[]> {
  let defs: FlowDefView[];
  try {
    defs = await ctx.tooling.query<FlowDefView>(
      'SELECT ApiName, IsActive, ActiveVersionId, LatestVersionId FROM FlowDefinitionView',
    );
  } catch {
    notes.push('FlowDefinitionView is not queryable; flow coupling skipped.');
    return [];
  }

  const summaries: FlowSummary[] = [];
  for (const d of defs) {
    const versionId = opts.includeInactive ? d.LatestVersionId ?? d.ActiveVersionId : d.ActiveVersionId;
    if (!versionId) continue;
    if (!opts.includeInactive && !d.IsActive) continue;
    try {
      const summary = await withCache(cache, 'flow', versionId, () => fetchFlowSummary(ctx.tooling, versionId, d.ApiName));
      if (summary) summaries.push(summary);
    } catch {
      notes.push(`Flow ${d.ApiName} metadata was unavailable; skipped.`);
    }
  }
  return summaries;
}

async function fetchFlowSummary(tooling: ToolingClient, versionId: string, apiName: string): Promise<FlowSummary> {
  const rows = await tooling.query<{ Metadata?: XmlObject }>(`SELECT Metadata FROM Flow WHERE Id = '${versionId}'`);
  const md = rows[0]?.Metadata;
  if (!md) throw new Error('no metadata');
  return summarizeFlow(md, apiName);
}

interface ApexClassRow {
  Name: string;
  NamespacePrefix: string | null;
  Body: string | null;
  SymbolTable: SymbolTableLike | null;
}
interface ApexTriggerRow extends ApexClassRow {
  TableEnumOrId: string;
}

export async function retrieveApex(
  ctx: IntelContext,
  resolver: ObjectResolver,
  notes: string[],
): Promise<{ classes: ApexClassInput[]; triggers: ApexTriggerInput[] }> {
  let classes: ApexClassInput[] = [];
  let triggers: ApexTriggerInput[] = [];

  try {
    const rows = await ctx.tooling.query<ApexClassRow>('SELECT Name, NamespacePrefix, Body, SymbolTable FROM ApexClass');
    classes = rows.map((r) => ({
      name: qualified(r.Name, r.NamespacePrefix),
      namespace: r.NamespacePrefix ?? null,
      body: usableBody(r.Body),
      symbolTable: r.SymbolTable ?? null,
    }));
  } catch {
    notes.push('ApexClass is not queryable; class coupling skipped.');
  }

  try {
    const rows = await ctx.tooling.query<ApexTriggerRow>(
      'SELECT Name, NamespacePrefix, TableEnumOrId, Body, SymbolTable FROM ApexTrigger',
    );
    triggers = rows
      .map((r) => ({
        name: qualified(r.Name, r.NamespacePrefix),
        namespace: r.NamespacePrefix ?? null,
        object: resolver.resolve(r.TableEnumOrId) ?? r.TableEnumOrId,
        body: usableBody(r.Body),
        symbolTable: r.SymbolTable ?? null,
      }))
      .filter((t) => !!t.object);
  } catch {
    notes.push('ApexTrigger is not queryable; trigger coupling skipped.');
  }

  return { classes, triggers };
}

function qualified(name: string, namespace: string | null): string {
  return namespace ? `${namespace}__${name}` : name;
}

/** Managed-package bodies come back as "(hidden)" — treat as no body (SymbolTable may still work). */
function usableBody(body: string | null): string | null {
  if (!body) return null;
  return body.trim() === '(hidden)' ? null : body;
}

async function withCache<T>(
  cache: OrgIntelCache | undefined,
  kind: string,
  key: string,
  compute: () => Promise<T>,
): Promise<T> {
  if (!cache) return compute();
  return cache.memoize(kind, key, compute);
}
