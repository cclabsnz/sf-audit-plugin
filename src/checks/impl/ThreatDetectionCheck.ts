import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface EventDateRow {
  EventDate: string;
}

// Real-Time Event Monitoring Threat Detection stores. GuestUserAnomalyEventStore is
// the one that flags anomalous guest bulk-access (the vector in guest-data leaks).
const ANOMALY_STORES = [
  'GuestUserAnomalyEventStore',
  'ApiAnomalyEventStore',
  'LoginAnomalyEventStore',
  'SessionHijackingEventStore',
  'CredentialStuffingEventStore',
  'ReportAnomalyEventStore',
];

/**
 * Verifies that Threat Detection event storage (especially Guest User Anomaly) is
 * available and retaining events. An empty/unavailable store means the one control
 * that would flag anomalous guest bulk-reads is blind, so a "no anomalies" result
 * is meaningless. This complements TransactionSecurityPolicyCheck (which looks at
 * policies, not whether anomaly events are actually stored).
 */
export class ThreatDetectionCheck implements SecurityCheck {
  readonly id = 'threat-detection';
  readonly name = 'Threat Detection Event Storage';
  readonly category = 'Monitoring';
  readonly description =
    'Verifies Real-Time Event Monitoring Threat Detection storage (Guest User Anomaly and siblings) is enabled and retaining events to detect anomalous guest bulk-access';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/EventManager/home`;

    const queryable: string[] = [];
    const withData: string[] = [];
    let guestStoreQueryable = false;

    for (const store of ANOMALY_STORES) {
      try {
        const rows = await ctx.soql.queryAll<EventDateRow>(
          `SELECT EventDate FROM ${store} WHERE EventDate = LAST_N_DAYS:180 LIMIT 1`,
        );
        queryable.push(store);
        if (store === 'GuestUserAnomalyEventStore') guestStoreQueryable = true;
        if (rows.length > 0) withData.push(store);
      } catch {
        // Store not present / not queryable (Threat Detection not licensed or storage off).
      }
    }

    if (queryable.length === 0) {
      findings.push({
        id: 'threat-detection-unavailable',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: 'Threat Detection event storage is not available',
        detail:
          'No Threat Detection anomaly store (e.g. GuestUserAnomalyEventStore) is queryable. Real-Time Event Monitoring / Threat Detection is not licensed or its storage is disabled, so anomalous guest bulk-access cannot be detected or investigated.',
        remediation:
          'Enable Real-Time Event Monitoring and turn on storage for the Threat Detection events (Setup > Event Manager), especially Guest User Anomaly. Add alerting/automation on these events.',
        affectedItems: [{ label: 'Event Manager', url: setupUrl, note: 'Enable Threat Detection event storage' }],
      });
      return { findings };
    }

    if (!guestStoreQueryable) {
      findings.push({
        id: 'threat-detection-guest-anomaly-missing',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: 'Guest User Anomaly detection store is not available',
        detail:
          'Other Threat Detection stores exist, but GuestUserAnomalyEventStore is not queryable, so anomalous guest bulk-access is not being detected or retained.',
        remediation: 'Enable storage for the Guest User Anomaly event in Setup > Event Manager and add alerting.',
        affectedItems: [{ label: 'Event Manager', url: setupUrl }],
      });
      return { findings };
    }

    // Empty stores are not a failure: Threat Detection writes an event only when it detects an
    // anomaly. They are not a pass either, because storage is switched on per event in Event
    // Manager and a store with storage off is queryable and empty too. No API exposes that toggle,
    // so the result is inconclusive. See ApiAnomalyEventStore:
    // https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_apianomalyeventstore.htm
    // and ApiAnomalyEvent:
    // https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_apianomalyevent.htm
    if (withData.length === 0) {
      findings.push({
        id: 'threat-detection-inactive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'No Threat Detection anomalies stored in 180 days; storage enablement not verified',
        detail:
          `The Threat Detection anomaly stores, including Guest User Anomaly, are queryable (${queryable.join(', ')}) and hold no events in the last 180 days. That is what an org with no detected anomalies looks like, and also what it looks like when storage is switched off for those events, which this audit cannot read.`,
        remediation:
          'In Setup > Event Manager, confirm Enable Storage is on for each Threat Detection event, and make sure alerting or automation acts on them when they occur.',
        affectedItems: [{ label: 'Event Manager', url: setupUrl }],
      });
      return { findings };
    }

    findings.push({
      id: 'threat-detection-active',
      category: this.category,
      riskLevel: 'LOW',
      passed: true,
      title: `Threat Detection storage active (${withData.length}/${queryable.length} stores have recent events)`,
      detail: `Guest User Anomaly detection is available and Threat Detection events are being stored (${withData.join(', ')}).`,
      remediation: 'Keep storage enabled and ensure alerting/automation acts on Guest User Anomaly events.',
    });
    return { findings };
  }
}
