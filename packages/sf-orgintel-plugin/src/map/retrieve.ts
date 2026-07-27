import type { ToolingClient } from '@cclabsnz/sf-core';
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

/**
 * Salesforce error text, trimmed to something that fits in a note.
 *
 * Swallowing these is how `intel map` silently produced an Apex-only graph against a real org
 * while reporting only "not queryable" — the operator could not tell a permissions problem from
 * a wrong-API bug. A degraded run must always say *why* it degraded.
 */
function describeError(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  const oneLine = raw.replace(/\s+/g, ' ').trim();
  return oneLine.length > 180 ? oneLine.slice(0, 177) + '…' : oneLine;
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
    // FlowDefinitionView is a STANDARD object, not a Tooling one — the Tooling endpoint answers
    // "sObject type 'FlowDefinitionView' is not supported." (Flow.Metadata below *is* Tooling.)
    defs = await ctx.soql.queryAll<FlowDefView>(
      'SELECT ApiName, IsActive, ActiveVersionId, LatestVersionId FROM FlowDefinitionView',
    );
  } catch (e) {
    notes.push(`FlowDefinitionView is not queryable; flow coupling skipped. (${describeError(e)})`);
    return [];
  }

  const wanted: Array<{ id: string; apiName: string }> = [];
  let managed = 0;
  for (const d of defs) {
    const versionId = opts.includeInactive ? d.LatestVersionId ?? d.ActiveVersionId : d.ActiveVersionId;
    if (!versionId) continue;
    if (!opts.includeInactive && !d.IsActive) continue;
    // Managed-package flows come back with a durable name (`ns__Flow-1`) instead of an Id.
    // Their metadata is not readable anyway, so skip them rather than emit a SOQL error each.
    if (!isSalesforceId(versionId)) {
      managed++;
      continue;
    }
    wanted.push({ id: versionId, apiName: d.ApiName });
  }
  if (managed > 0) {
    notes.push(`${managed} managed-package flow(s) skipped — metadata is not readable for managed flows.`);
  }

  // Serve what the cache already has, then fetch only the misses — in batches, because one
  // Tooling round trip per flow took 7 minutes on a real org with ~300 flows.
  const summaries: FlowSummary[] = [];
  const misses: Array<{ id: string; apiName: string }> = [];
  for (const w of wanted) {
    const hit = cache?.get<FlowSummary>('flow', contentHash(w.id)) ?? null;
    if (hit) summaries.push(hit);
    else misses.push(w);
  }

  // The Tooling API refuses multi-row retrieval of Metadata/FullName ("the query
  // qualifications must specify no more than one row"), so each flow needs its own query.
  // Bounded concurrency is the only lever: ~300 sequential round trips took 7 minutes.
  await mapWithConcurrency(misses, FLOW_CONCURRENCY, async (w) => {
    let rows: Array<{ Id?: string; Metadata?: XmlObject }>;
    try {
      rows = await ctx.tooling.query<{ Id?: string; Metadata?: XmlObject }>(
        `SELECT Id, Metadata FROM Flow WHERE Id = '${w.id}'`,
      );
    } catch (e) {
      notes.push(`Flow ${w.apiName} metadata was unavailable; skipped. (${describeError(e)})`);
      return;
    }
    const md = rows[0]?.Metadata;
    if (!md) {
      notes.push(`Flow ${w.apiName} returned no metadata; skipped.`);
      return;
    }
    try {
      const summary = summarizeFlow(md, w.apiName);
      summaries.push(summary);
      cache?.set('flow', contentHash(w.id), summary);
    } catch (e) {
      notes.push(`Flow ${w.apiName} could not be parsed; skipped. (${describeError(e)})`);
    }
  });
  // Deterministic regardless of completion order.
  notes.sort();
  return summaries.sort((a, b) => a.apiName.localeCompare(b.apiName));
}

/** Concurrent Tooling requests in flight while fetching flow metadata. */
const FLOW_CONCURRENCY = 8;

/**
 * True for a real 15- or 18-character Salesforce Id. FlowDefinitionView returns a durable
 * name (`ns__Flow-1`) instead of an Id for managed-package flows; feeding that to a WHERE
 * clause yields "invalid ID field".
 */
function isSalesforceId(v: string): boolean {
  return /^[a-zA-Z0-9]{15}$|^[a-zA-Z0-9]{18}$/.test(v);
}

/** Run `fn` over items with at most `limit` in flight. Order of completion is not preserved. */
async function mapWithConcurrency<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]);
    }
  });
  await Promise.all(workers);
}

interface ApexClassRow {
  Name: string;
  NamespacePrefix: string | null;
  Body: string | null;
  SymbolTable: SymbolTableLike | null;
}
/** ApexTrigger has no SymbolTable column — only ApexClass does. Body drives the fallback. */
interface ApexTriggerRow extends Omit<ApexClassRow, 'SymbolTable'> {
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
  } catch (e) {
    notes.push(`ApexClass is not queryable; class coupling skipped. (${describeError(e)})`);
  }

  try {
    const rows = await ctx.tooling.query<ApexTriggerRow>(
      'SELECT Name, NamespacePrefix, TableEnumOrId, Body FROM ApexTrigger',
    );
    triggers = rows
      .map((r) => ({
        name: qualified(r.Name, r.NamespacePrefix),
        namespace: r.NamespacePrefix ?? null,
        object: resolver.resolve(r.TableEnumOrId) ?? r.TableEnumOrId,
        body: usableBody(r.Body),
        symbolTable: null,
      }))
      .filter((t) => !!t.object);
  } catch (e) {
    notes.push(`ApexTrigger is not queryable; trigger coupling skipped. (${describeError(e)})`);
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
