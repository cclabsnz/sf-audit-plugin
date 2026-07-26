import type { IntelContext } from '../lib/wire.js';
import type { ProbeData } from './types.js';
import { buildOrgBasics } from './orgBasics.js';
import { probeEventMonitoring } from './eventMonitoring.js';
import { probeFieldHistory } from './fieldHistory.js';
import { probeBehavioralTables } from './behavioralTables.js';
import { computeEvidenceTier } from './evidenceTier.js';
import { buildCoverage } from './coverage.js';
import { buildRecommendations } from './recommendations.js';
import {
  fetchSObjectCatalog,
  buildCatalog,
  historyObjectName,
  type SObjectCatalog,
} from './sobjectCatalog.js';

/**
 * Run the full capability probe. Pure over the context's read-only clients and deterministic:
 * the same org state produces the same ProbeData (provenance/timestamps are added by the caller).
 */
export async function runProbe(ctx: IntelContext): Promise<ProbeData> {
  const org = buildOrgBasics(ctx);

  let catalog: SObjectCatalog;
  try {
    catalog = await fetchSObjectCatalog(ctx.rest);
  } catch {
    catalog = buildCatalog([]);
  }
  const hasCatalog = catalog.all().length > 0;

  const eventMonitoring = await probeEventMonitoring(ctx.soql);
  const fieldHistory = await probeFieldHistory(ctx.soql, catalog);

  const enabledHistoryTables = fieldHistory.objects
    .filter((o) => o.historyTrackingEnabled)
    .map((o) => historyObjectName(o.object, o.custom));
  const behavioralTables = await probeBehavioralTables(ctx.soql, enabledHistoryTables);

  const evidenceTier = computeEvidenceTier(eventMonitoring, fieldHistory, behavioralTables, hasCatalog);
  const coverage = buildCoverage(eventMonitoring, fieldHistory, behavioralTables);
  const recommendations = buildRecommendations(org, eventMonitoring, fieldHistory, behavioralTables, catalog);

  return {
    org,
    eventMonitoring,
    fieldHistory,
    behavioralTables,
    evidenceTier,
    coverage,
    recommendations,
  };
}
