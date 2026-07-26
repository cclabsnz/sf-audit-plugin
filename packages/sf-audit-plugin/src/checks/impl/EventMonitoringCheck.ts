import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { classifyEventLogAccessError } from '@cclabsnz/sf-core';

interface EventLogGroupRecord {
  EventType: string;
  fileCount: number;
  earliestDate: string;
}

export class EventMonitoringCheck implements SecurityCheck {
  readonly id = 'event-monitoring';
  readonly name = 'Event Monitoring Storage';
  readonly category = 'Event Monitoring';
  readonly description = 'SBS-MON-001 / SBS-INT-004: verifies Event Monitoring is enabled and logs cover at least 30 days';

  readonly populatesCache = ['eventLogSummary'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/EventLogFile/home`;

    try {
      // Single aggregated query: one row per event type, with earliest log date and file count.
      // Zero results means Event Monitoring is not enabled or not licensed.
      const result = await ctx.soql.query<EventLogGroupRecord>(
        `SELECT EventType, COUNT(Id) fileCount, MIN(LogDate) earliestDate
         FROM EventLogFile
         WHERE LogDate > LAST_N_DAYS:35
         GROUP BY EventType
         ORDER BY COUNT(Id) DESC`
      );

      const groups = result.records;
      const totalFiles = groups.reduce((sum, r) => sum + (r.fileCount ?? 0), 0);
      const eventTypes = groups.map((r) => r.EventType);

      const earliestDate = groups.reduce<string | null>((earliest, r) => {
        if (!r.earliestDate) return earliest;
        if (!earliest) return r.earliestDate;
        return r.earliestDate < earliest ? r.earliestDate : earliest;
      }, null);

      // Populate cache for SiemIntegrationCheck + GuestTrafficAnomalyCheck at zero extra API cost
      ctx.cache.eventLogSummary = { earliestDate, totalFiles, eventTypes, accessible: true };

      if (totalFiles === 0) {
        findings.push({
          id: 'event-monitoring-disabled',
          category: this.category,
          riskLevel: 'HIGH',
          title: 'No Event Monitoring log files found in the last 35 days: SBS-MON-001',
          detail:
            'SBS-MON-001 requires Event Monitoring storage to be enabled so that login, API access, and data export events are captured. No EventLogFile records exist for the past 35 days, indicating Event Monitoring is either not licensed or not configured.',
          remediation:
            'Enable Event Monitoring in Setup → Event Monitoring Settings. If the feature is not licensed, raise with your Salesforce account team. SBS-MON-001 compliance requires it.',
          affectedItems: [{ label: 'Event Monitoring Setup', url: setupUrl, note: 'Enable event log storage' }],
        });
        return { findings };
      }

      // SBS-MON-001: inventory of what is being captured
      findings.push({
        id: 'event-monitoring-enabled',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `Event Monitoring active: ${totalFiles} log file(s) across ${eventTypes.length} event type(s) (SBS-MON-001)`,
        detail: `SBS-MON-001 requires Event Monitoring to be enabled and actively capturing events. Found ${totalFiles} EventLogFile records covering ${eventTypes.length} distinct event types over the past 35 days. Event types captured: ${eventTypes.slice(0, 12).join(', ')}${eventTypes.length > 12 ? ` (+${eventTypes.length - 12} more)` : ''}.`,
        remediation: 'Review the list of monitored event types and ensure Login, API, DataExport, and LightningInteraction events are included.',
      });

      // SBS-INT-004: API event logs must be retained for at least 30 days
      if (earliestDate) {
        const daysCovered = Math.ceil(
          (Date.now() - new Date(earliestDate).getTime()) / 86_400_000
        );

        if (daysCovered < 30) {
          findings.push({
            id: 'event-monitoring-retention-short',
            category: this.category,
            riskLevel: 'MEDIUM',
            title: `Event logs cover only ${daysCovered} day(s): SBS-INT-004 requires 30-day minimum`,
            detail:
              `SBS-INT-004 requires API event logs to be retained for at least 30 days to support incident investigation. The earliest EventLogFile available is from ${new Date(earliestDate).toISOString().split('T')[0]}, giving only ${daysCovered} day(s) of coverage within the past 35-day window.`,
            remediation:
              `Export EventLogFile records to an external storage system or SIEM on a daily or weekly basis to maintain 30+ days of retention. Salesforce's native event log retention is typically 1–30 days depending on edition and Event Monitoring tier.`,
          });
        }
      }
    } catch (e) {
      // EventLogFile may not be accessible without Event Monitoring license, or the
      // audit user may lack "View Event Log Files". Record which, so downstream
      // checks can phrase their blind spot precisely instead of re-querying.
      ctx.cache.eventLogSummary = { earliestDate: null, totalFiles: 0, eventTypes: [], accessible: false, accessError: classifyEventLogAccessError(e) };
      findings.push({
        id: 'event-monitoring-inaccessible',
        category: this.category,
        riskLevel: 'MEDIUM',
        inconclusive: true,
        title: 'Event Monitoring log files could not be accessed: SBS-MON-001 cannot be verified',
        detail:
          'SBS-MON-001 requires Event Monitoring storage to be enabled. EventLogFile was not accessible. This may indicate the feature is not licensed or the audit user lacks the "View Event Log Files" permission.',
        remediation:
          'Grant "View Event Log Files" permission to the audit user, or verify Event Monitoring is licensed and enabled in Setup → Event Monitoring Settings.',
      });
    }

    return { findings };
  }
}
