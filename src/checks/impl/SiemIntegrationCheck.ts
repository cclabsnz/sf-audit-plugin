import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Known SIEM and log-forwarding service hostname/name patterns
const SIEM_ENDPOINT_PATTERNS = [
  /splunk/i, /sumo[\s-]*logic/i, /sumologic/i, /datadog/i,
  /elastic(?:search|\.co)/i, /logstash/i, /kibana/i,
  /new[\s-]*relic/i, /dynatrace/i, /logrhythm/i,
  /securonix/i, /qradar/i, /arcsight/i,
  /microsoft[\s-]*sentinel/i, /azure[\s-]*sentinel/i,
  /loggly/i, /papertrail/i, /\bsiem\b/i,
];

const SIEM_APP_PATTERNS = [
  /splunk/i, /datadog/i, /sumo/i, /elastic/i, /new[\s-]*relic/i,
  /dynatrace/i, /\bsiem\b/i, /log[\s-]*forward/i, /event[\s-]*export/i,
];

const SIEM_APEX_PATTERNS = [
  /splunk/i, /datadog/i, /sumo/i, /elastic/i,
  /LogForward/i, /SiemSync/i, /EventExport/i, /LogShipper/i,
];

export class SiemIntegrationCheck implements SecurityCheck {
  readonly id = 'siem-integration';
  readonly name = 'SIEM Integration Signals';
  readonly category = 'Event Monitoring';
  readonly description = 'SBS-MON-003/004: detects evidence of SIEM or external monitoring integration using cached org data (zero extra queries)';

  // All five caches are read-only — no new API calls needed
  readonly dependsOnCache = [
    'namedCredentialEndpoints',
    'remoteSiteUrls',
    'connectedAppNames',
    'scheduledApexClassNames',
    'eventLogSummary',
  ] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const namedCredEndpoints = ctx.cache.namedCredentialEndpoints ?? [];
    const remoteSiteUrls = ctx.cache.remoteSiteUrls ?? [];
    const connectedAppNames = ctx.cache.connectedAppNames ?? [];
    const scheduledApexNames = ctx.cache.scheduledApexClassNames ?? [];
    const eventLogSummary = ctx.cache.eventLogSummary;

    // Collect positive signals of external monitoring integration
    const siemNamedCreds = namedCredEndpoints.filter((url) =>
      SIEM_ENDPOINT_PATTERNS.some((p) => p.test(url))
    );
    const siemRemoteSites = remoteSiteUrls.filter((url) =>
      SIEM_ENDPOINT_PATTERNS.some((p) => p.test(url))
    );
    const siemApps = connectedAppNames.filter((name) =>
      SIEM_APP_PATTERNS.some((p) => p.test(name))
    );
    const siemApex = scheduledApexNames.filter((name) =>
      SIEM_APEX_PATTERNS.some((p) => p.test(name))
    );

    const totalSignals = siemNamedCreds.length + siemRemoteSites.length + siemApps.length + siemApex.length;

    const signalSources: Array<{ label: string; note: string }> = [
      ...siemNamedCreds.map((u) => ({ label: u, note: 'Named Credential endpoint' })),
      ...siemRemoteSites.map((u) => ({ label: u, note: 'Remote Site URL' })),
      ...siemApps.map((n) => ({ label: n, note: 'Connected App' })),
      ...siemApex.map((n) => ({ label: n, note: 'Scheduled Apex class' })),
    ];

    if (totalSignals > 0) {
      const signalSummary = [
        siemNamedCreds.length > 0 && `Named Credentials: ${siemNamedCreds.join(', ')}`,
        siemRemoteSites.length > 0 && `Remote Sites: ${siemRemoteSites.join(', ')}`,
        siemApps.length > 0 && `Connected Apps: ${siemApps.join(', ')}`,
        siemApex.length > 0 && `Scheduled Apex: ${siemApex.join(', ')}`,
      ]
        .filter(Boolean)
        .join('; ');

      findings.push({
        id: 'siem-integration-detected',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${totalSignals} SIEM/monitoring integration signal(s) detected: SBS-MON-003/004`,
        detail:
          `SBS-MON-003 requires suspicious login activity to be monitored and alerted on. SBS-MON-004 requires API activity anomalies to be detected. Both controls require integration with an external monitoring system. ${totalSignals} signal(s) suggest external monitoring is in place. Sources: ${signalSummary}.`,
        remediation:
          'Verify the integration is actively receiving and alerting on Login, API, and DataExport events. Confirm alert thresholds cover: multiple failed logins, off-hours access, bulk data export, and unusual geographic login patterns (SBS-MON-003). Confirm API anomaly detection is configured (SBS-MON-004).',
        affectedItems: signalSources.map((s) => ({
          label: s.label,
          url: `${baseUrl}/lightning/setup/home`,
          note: s.note,
        })),
      });
    } else {
      findings.push({
        id: 'siem-integration-not-detected',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'No SIEM or external monitoring integration detected: SBS-MON-003/004',
        detail:
          'SBS-MON-003 requires suspicious login activity to be monitored and alerted on. SBS-MON-004 requires API activity anomalies to be detected. No signals of an external monitoring or SIEM integration were found across Named Credentials, Remote Sites, Connected Apps, or Scheduled Apex jobs. Without external log forwarding, Event Monitoring data remains unanalysed and no automated alerts can be generated.',
        remediation:
          'Integrate Salesforce Event Monitoring with a SIEM platform (Splunk, Datadog, Sumo Logic, Microsoft Sentinel, etc.) using the EventLogFile API or Salesforce Shield Event Streaming. Configure alerts for: repeated failed logins, off-hours API access, bulk data export events, and unusual login geolocations (SBS-MON-003). Enable API usage anomaly detection (SBS-MON-004).',
      });
    }

    // Additional signal: check if event logs cover sufficient days for SIEM ingestion
    if (eventLogSummary && eventLogSummary.totalFiles > 0 && eventLogSummary.earliestDate) {
      const daysCovered = Math.ceil(
        (Date.now() - new Date(eventLogSummary.earliestDate).getTime()) / 86_400_000
      );

      if (daysCovered < 30 && totalSignals === 0) {
        findings.push({
          id: 'siem-retention-gap',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `Event logs cover only ${daysCovered} day(s) in Salesforce: SIEM ingestion needed for SBS-INT-004 compliance`,
          detail:
            'SBS-INT-004 requires 30 days of API event log retention. Without a SIEM or log archival process ingesting logs daily, native Salesforce retention may be insufficient. Logs older than the native retention window will be permanently lost.',
          remediation:
            `Configure a SIEM or log archival process to ingest EventLogFile records at least daily. This ensures the 30-day retention requirement is met independent of Salesforce's native retention window.`,
        });
      }
    }

    return { findings };
  }
}
