import type { EvidenceTier, CouplingGraph, LandscapeManifest } from '@cclabsnz/sf-core';
import type { IntelContext } from '../lib/wire.js';
import type { OrgIntelCache } from '../lib/cache.js';
import type { Cluster } from './graph/clusters.js';
import type { Point } from './graph/layout.js';
import { fetchSObjectCatalog, buildCatalog, type SObjectCatalog } from '../probe/sobjectCatalog.js';
import { countRows } from '../probe/query.js';
import { buildObjectResolver } from '../discover/objectResolver.js';
import { buildAutomationIndex } from '../discover/automation.js';
import { retrieveFlows, retrieveApex } from './retrieve.js';
import { deriveFlowEdges } from './flow/flowEdges.js';
import { deriveApexEdges } from './apex/apexEdges.js';
import { mergeEdges, type NodeInfo } from './graph/couplingGraph.js';
import { assembleCouplingArtifacts } from './assemble.js';

export interface MapProvenanceInput {
  generatedAt: string;
  toolVersion: string;
  orgId: string;
  evidenceTier: EvidenceTier;
}

export interface MapOptions {
  includeInactive?: boolean;
  topLayout?: number;
  cache?: OrgIntelCache;
  maxNodeCounts?: number;
}

export interface MapRunResult {
  couplingGraph: CouplingGraph;
  manifest: LandscapeManifest;
  clusters: Cluster[];
  layout: Map<string, Point>;
  flowsAnalyzed: number;
  apexClassesAnalyzed: number;
  apexTriggersAnalyzed: number;
  notes: string[];
}

/** Retrieve flows + apex, build the coupling graph and landscape manifest. Read-only. */
export async function runMap(
  ctx: IntelContext,
  provenance: MapProvenanceInput,
  opts: MapOptions = {},
): Promise<MapRunResult> {
  const notes: string[] = [];
  const maxNodeCounts = opts.maxNodeCounts ?? 100;

  let catalog: SObjectCatalog;
  try {
    catalog = await fetchSObjectCatalog(ctx.rest);
  } catch {
    catalog = buildCatalog([]);
  }
  const known = new Set(catalog.all().map((s) => s.name));

  const resolver = await buildObjectResolver(ctx.tooling);
  const automation = await buildAutomationIndex(ctx.soql, ctx.tooling, resolver, catalog);
  notes.push(...automation.notes);

  const flows = await retrieveFlows(ctx, { includeInactive: opts.includeInactive }, notes, opts.cache);
  const apex = await retrieveApex(ctx, resolver, notes);

  // Determine the object set that will appear in the graph, then fetch 90-day counts for it.
  const preEdges = mergeEdges([
    ...deriveFlowEdges(flows).edges,
    ...deriveApexEdges(apex.classes, apex.triggers, known),
  ]);
  const objectSet = new Set<string>();
  for (const e of preEdges) {
    objectSet.add(e.from);
    objectSet.add(e.to);
  }
  const recordCounts = await fetchRecordCounts(ctx, [...objectSet], maxNodeCounts, notes);

  const nodeInfo = (object: string): NodeInfo => {
    const c = automation.countsFor(object);
    return {
      custom: catalog.get(object)?.custom ?? /__c$/i.test(object),
      automationCounts: { flows: c.flows, triggers: c.triggers, approvals: c.approvals },
      recordCount90d: recordCounts.get(object) ?? 0,
    };
  };
  const labelOf = (object: string): string => catalog.get(object)?.label ?? object;

  const artifacts = assembleCouplingArtifacts({
    flowSummaries: flows,
    apexClasses: apex.classes,
    apexTriggers: apex.triggers,
    knownObjects: known,
    nodeInfo,
    labelOf,
    topLayout: opts.topLayout,
    notes,
    couplingProvenance: {
      tool: 'orgintel',
      toolVersion: provenance.toolVersion,
      generatedAt: provenance.generatedAt,
      orgId: provenance.orgId,
      evidenceTier: provenance.evidenceTier,
    },
    manifestProvenance: {
      tool: 'orgintel',
      toolVersion: provenance.toolVersion,
      generatedAt: provenance.generatedAt,
      orgId: provenance.orgId,
    },
  });

  return {
    couplingGraph: artifacts.couplingGraph,
    manifest: artifacts.manifest,
    clusters: artifacts.clusters,
    layout: artifacts.layout,
    flowsAnalyzed: flows.length,
    apexClassesAnalyzed: apex.classes.length,
    apexTriggersAnalyzed: apex.triggers.length,
    notes: artifacts.notes,
  };
}

async function fetchRecordCounts(
  ctx: IntelContext,
  objects: string[],
  cap: number,
  notes: string[],
): Promise<Map<string, number>> {
  const counts = new Map<string, number>();
  const sorted = [...objects].sort();
  const take = sorted.slice(0, cap);
  if (sorted.length > take.length) {
    notes.push(`Record counts computed for ${cap} of ${sorted.length} graph objects.`);
  }
  for (const o of take) {
    try {
      counts.set(o, await countRows(ctx.soql, o, 'CreatedDate = LAST_N_DAYS:90'));
    } catch {
      counts.set(o, 0);
    }
  }
  return counts;
}
