import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LimitEntry { Max: number; Remaining: number; }
type OrgLimits = Record<string, LimitEntry>;

const LIMITS_TO_CHECK = [
  { key: 'DailyApiRequests', label: 'Daily API Requests' },
  { key: 'DailyBulkApiRequests', label: 'Daily Bulk API Requests' },
  { key: 'DailyAsyncApexExecutions', label: 'Daily Async Apex Executions' },
  { key: 'DataStorageMB', label: 'Data Storage (MB)' },
  { key: 'FileStorageMB', label: 'File Storage (MB)' },
  { key: 'SingleEmail', label: 'Single Email' },
  { key: 'MassEmail', label: 'Mass Email' },
  { key: 'StreamingApiConcurrentClients', label: 'Streaming API Concurrent Clients' },
];

export class ApiLimitsCheck implements SecurityCheck {
  readonly id = 'api-limits';
  readonly name = 'API and Resource Limits';
  readonly category = 'Resource Management';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    const limits = await ctx.rest.get<OrgLimits>('/limits');

    const overThresholdLimits: Array<{ label: string; usedPct: number; Max: number; Used: number }> = [];

    for (const { key, label } of LIMITS_TO_CHECK) {
      const entry = limits[key];
      if (!entry) continue;

      const { Max, Remaining } = entry;
      if (Max === 0) continue;

      const Used = Max - Remaining;
      const usedPct = (Used / Max) * 100;

      if (usedPct > 50) {
        overThresholdLimits.push({ label, usedPct, Max, Used });
      }
    }

    if (overThresholdLimits.length > 0) {
      for (const { label, usedPct, Max, Used } of overThresholdLimits) {
        let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
        if (usedPct > 90) riskLevel = 'CRITICAL';
        else if (usedPct > 75) riskLevel = 'HIGH';
        else riskLevel = 'MEDIUM';

        findings.push({
          id: `api-limit-${label.toLowerCase().replace(/\s+/g, '-')}`,
          category: this.category,
          riskLevel,
          title: `${label}: ${usedPct.toFixed(0)}% used (${Used} of ${Max})`,
          detail: `Org limit ${label} is at ${usedPct.toFixed(1)}% utilization. High usage increases the risk of governor limit failures.`,
          remediation: 'Review usage patterns and consider requesting a limit increase, optimizing batch job scheduling, or archiving data.',
        });
      }
    } else {
      findings.push({
        id: 'api-limits-healthy',
        category: this.category,
        riskLevel: 'LOW',
        title: 'All monitored API limits are within acceptable thresholds',
        detail: 'All monitored API and resource limits are below 50% utilization.',
        remediation: 'Continue monitoring limits as org activity grows.',
      });
    }

    return { findings };
  }
}
