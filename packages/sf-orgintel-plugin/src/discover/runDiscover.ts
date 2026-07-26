import type { IntelContext } from '../lib/wire.js';
import type { DiscoverData, AnchorSignals, StatusPicklistRef } from './types.js';
import { DEFAULT_WEIGHTS, type DiscoverWeights } from './scoringConfig.js';
import {
  fetchSObjectCatalog,
  buildCatalog,
  KEY_STANDARD_OBJECTS,
  customBusinessObjects,
  historyObjectName,
  type SObjectCatalog,
} from '../probe/sobjectCatalog.js';
import { buildObjectResolver } from './objectResolver.js';
import { buildAutomationIndex } from './automation.js';
import { fetchObjectDescribe, extractInsight } from './objectInsight.js';
import { objectVolume } from './volume.js';
import { activityAttach } from './activity.js';
import { scoreAnchors, type RawCandidate } from './score.js';
import { buildFingerprint } from './fingerprint.js';

export interface DiscoverOptions {
  topN?: number;
  maxObjects?: number;
  shortlist?: number;
  weights?: DiscoverWeights;
}

interface Target {
  name: string;
  label: string;
  custom: boolean;
}

/**
 * Rank the org's likely process-anchor objects and emit a domain fingerprint. Deterministic
 * and read-only: every signal is a pure function of current org state; ordering is stable.
 */
export async function runDiscover(ctx: IntelContext, opts: DiscoverOptions = {}): Promise<DiscoverData> {
  const topN = opts.topN ?? 10;
  const maxObjects = opts.maxObjects ?? 150;
  const shortlistSize = opts.shortlist ?? 25;
  const weights = opts.weights ?? DEFAULT_WEIGHTS;
  const notes: string[] = [];

  let catalog: SObjectCatalog;
  try {
    catalog = await fetchSObjectCatalog(ctx.rest);
  } catch {
    catalog = buildCatalog([]);
  }

  const resolver = await buildObjectResolver(ctx.tooling);
  const automation = await buildAutomationIndex(ctx.soql, ctx.tooling, resolver, catalog);
  notes.push(...automation.notes);

  const targets = selectTargets(catalog, automation.automatedObjects(), maxObjects);
  const droppedObjects = targets.dropped;
  if (droppedObjects > 0) {
    notes.push(
      `Analysed ${maxObjects} of ${targets.total} candidate objects; ${droppedObjects} lower-priority custom objects were not scored.`,
    );
  }

  const statusPicklists: StatusPicklistRef[] = [];
  const raw: RawCandidate[] = [];
  for (const t of targets.list) {
    const describe = await fetchObjectDescribe(ctx.rest, t.name);
    const insight = describe
      ? extractInsight(describe)
      : { object: t.name, label: t.label, statusField: null, inboundReferences: 0 };
    const vol = await objectVolume(ctx.soql, t.name);
    const histName = historyObjectName(t.name, t.custom);
    const historyTracking = catalog.has(histName) && catalog.isQueryable(histName);

    if (insight.statusField) {
      statusPicklists.push({ object: t.name, field: insight.statusField.field, values: insight.statusField.values });
    }

    const signals: AnchorSignals = {
      automation: automation.countsFor(t.name),
      statusField: insight.statusField,
      totalRecords: vol.total,
      created90d: vol.created90d,
      inboundReferences: insight.inboundReferences,
      activityAttach: null,
      activityApproximate: true,
      historyTracking,
    };
    raw.push({ object: t.name, label: insight.label ?? t.label, custom: t.custom, signals });
  }

  // Preliminary rank (activity contributes 0), then compute activity for the top shortlist only.
  const prelim = scoreAnchors(raw, weights);
  const shortlist = new Set(prelim.slice(0, shortlistSize).map((c) => c.object));
  for (const c of raw) {
    if (shortlist.has(c.object)) {
      c.signals.activityAttach = await activityAttach(ctx.soql, c.object);
    }
  }
  const anchors = scoreAnchors(raw, weights).slice(0, topN);

  const fingerprint = await buildFingerprint(ctx, catalog, statusPicklists);

  return {
    org: { orgId: ctx.orgInfo.id, name: ctx.orgInfo.name },
    anchors,
    totalObjectsAnalyzed: targets.list.length,
    droppedObjects,
    fingerprint,
    weights: { ...weights },
    notes,
  };
}

function selectTargets(
  catalog: SObjectCatalog,
  automated: Set<string>,
  maxObjects: number,
): { list: Target[]; total: number; dropped: number } {
  const keyStd: Target[] = KEY_STANDARD_OBJECTS.filter((o) => catalog.has(o)).map((o) => ({
    name: o,
    label: catalog.get(o)?.label ?? o,
    custom: false,
  }));
  const customs: Target[] = customBusinessObjects(catalog).map((s) => ({
    name: s.name,
    label: s.label,
    custom: true,
  }));
  // Prioritise automated custom objects, then alphabetical — deterministic.
  customs.sort((a, b) => {
    const aa = automated.has(a.name) ? 1 : 0;
    const ba = automated.has(b.name) ? 1 : 0;
    return ba - aa || a.name.localeCompare(b.name);
  });
  const all = [...keyStd, ...customs];
  const list = all.slice(0, maxObjects);
  return { list, total: all.length, dropped: all.length - list.length };
}
