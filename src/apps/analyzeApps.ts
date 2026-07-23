import type { AppFinding } from './types.js';
import type { SoqlClient } from '../api/SoqlClient.js';
import { collectUsage } from './usageCollector.js';
import { resolveApps } from './appResolver.js';
import { computeGranted } from './grantedAccess.js';
import { buildFinding } from './leastPrivilege.js';

export async function analyzeApps(
  restApiCsv: string,
  soql: SoqlClient,
  opts: { since: number; soakDays: number; soapApiCsv?: string },
): Promise<AppFinding[]> {
  const usage = collectUsage(restApiCsv, opts.soapApiCsv);
  const appIds = usage.usage.map((u) => u.appId);
  const allUsers = [...new Set(usage.usage.flatMap((u) => u.userIds))];
  const resolved = await resolveApps(appIds, soql, allUsers);
  const resolvedById = new Map(resolved.map((r) => [r.appId, r]));

  const findings: AppFinding[] = [];
  for (const u of usage.usage) {
    const app = resolvedById.get(u.appId)!;
    const granted = await computeGranted(u.appId, u.userIds, soql, null);
    findings.push(
      buildFinding(app, u, granted, { since: opts.since, attributionRatePct: usage.attributionRatePct }, opts.soakDays),
    );
  }
  return findings;
}
