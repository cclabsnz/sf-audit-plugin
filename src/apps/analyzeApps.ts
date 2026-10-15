import type { AppFinding } from './types.js';
import type { SoqlClient } from '@cclabsnz/sf-core';
import { collectUsage } from './usageCollector.js';
import { resolveApps } from './appResolver.js';
import { computeGranted } from './grantedAccess.js';
import { buildFinding } from './leastPrivilege.js';

export interface AnalyzeAppsOptions {
  since: number;
  soakDays: number;
  soapApiCsv?: string;
  bulkApi2Csv?: string;
  graphQlCsv?: string;
  auraCsv?: string;
  /** Why usage is known to be incomplete (e.g. some log files failed to download); suppresses revoke advice. */
  incompleteUsage?: string;
}

export async function analyzeApps(
  restApiCsv: string,
  soql: SoqlClient,
  opts: AnalyzeAppsOptions,
): Promise<AppFinding[]> {
  const usage = collectUsage(restApiCsv, {
    soapApiCsv: opts.soapApiCsv,
    bulkApi2Csv: opts.bulkApi2Csv,
    graphQlCsv: opts.graphQlCsv,
    auraCsv: opts.auraCsv,
  });
  const appIds = usage.usage.map((u) => u.appId);
  const allUsers = [...new Set(usage.usage.flatMap((u) => u.userIds))];
  const resolved = await resolveApps(appIds, soql, allUsers);
  const resolvedById = new Map(resolved.map((r) => [r.appId, r]));

  const findings: AppFinding[] = [];
  for (const u of usage.usage) {
    const app = resolvedById.get(u.appId)!;
    const granted = await computeGranted(u.appId, u.userIds, soql, null);
    findings.push(
      buildFinding(app, u, granted, { since: opts.since, attributionRatePct: usage.attributionRatePct }, opts.soakDays, opts.incompleteUsage),
    );
  }
  return findings;
}
