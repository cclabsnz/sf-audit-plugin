import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FieldHistoryGroupRecord {
  objectName: string;
  trackedCount: number;
}

// Sensitive standard objects SBS-DATA-004 requires history tracking on.
// Custom objects (e.g. Financial__c) are intentionally excluded — they may not exist.
const SENSITIVE_OBJECTS = [
  'Account', 'Contact', 'Lead', 'Opportunity', 'Case', 'Contract', 'Quote', 'User',
];

export class FieldHistoryTrackingCheck implements SecurityCheck {
  readonly id = 'field-history-tracking';
  readonly name = 'Field History Tracking';
  readonly category = 'Data Security';
  readonly description = 'SBS-DATA-004: verifies field history tracking is enabled on sensitive standard objects';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ObjectManager/home`;
    const objectList = SENSITIVE_OBJECTS.map((o) => `'${o}'`).join(', ');

    try {
      // Tooling API: count fields with history tracking enabled per sensitive object.
      // Objects with zero tracked fields will be absent from the result — those are violations.
      const results = await ctx.tooling.query<FieldHistoryGroupRecord>(
        `SELECT EntityDefinition.QualifiedApiName objectName, COUNT(Id) trackedCount
         FROM FieldDefinition
         WHERE EntityDefinition.QualifiedApiName IN (${objectList})
           AND IsFieldHistoryTracked = true
         GROUP BY EntityDefinition.QualifiedApiName`
      );

      const trackedMap = new Map<string, number>();
      for (const r of results) {
        trackedMap.set(r.objectName, r.trackedCount ?? 0);
      }

      const withTracking = SENSITIVE_OBJECTS.filter((o) => (trackedMap.get(o) ?? 0) > 0);
      const withoutTracking = SENSITIVE_OBJECTS.filter((o) => (trackedMap.get(o) ?? 0) === 0);

      if (withoutTracking.length === 0) {
        findings.push({
          id: 'field-history-tracking-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'Field history tracking enabled on all checked sensitive objects: SBS-DATA-004',
          detail: `SBS-DATA-004 requires field history tracking on sensitive objects to support incident investigation and compliance evidence. All ${SENSITIVE_OBJECTS.length} checked objects have at least one tracked field. Objects: ${withTracking.map((o) => `${o} (${trackedMap.get(o)} field(s))`).join(', ')}.`,
          remediation: 'Periodically review which specific fields are tracked to ensure key sensitive fields (email address, phone, revenue, status) are included.',
        });
        return { findings };
      }

      findings.push({
        id: 'field-history-tracking-missing',
        category: this.category,
        riskLevel: withoutTracking.length >= 3 ? 'HIGH' : 'MEDIUM',
        title: `${withoutTracking.length} sensitive object(s) have no field history tracking: SBS-DATA-004`,
        detail:
          `SBS-DATA-004 requires field history tracking on sensitive objects to capture who changed what data and when, enabling post-incident investigation and audit evidence. The following objects have no tracked fields: ${withoutTracking.join(', ')}. ${withTracking.length > 0 ? `Objects already configured: ${withTracking.map((o) => `${o} (${trackedMap.get(o)} field(s))`).join(', ')}.` : ''}`,
        remediation:
          'Enable field history tracking on each listed object in Setup → Object Manager → [Object] → Fields & Relationships → Set History Tracking. At minimum track key sensitive fields: email addresses, phone numbers, revenue fields, owner changes, and status changes.',
        affectedItems: withoutTracking.map((name) => ({
          label: name,
          url: `${setupUrl}/list?objectType=${name}`,
          note: 'No fields have history tracking enabled: configure via Object Manager → Set History Tracking',
        })),
      });
    } catch {
      findings.push({
        id: 'field-history-tracking-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Field history tracking status could not be determined',
        detail:
          'SBS-DATA-004 requires field history tracking on sensitive objects. The Tooling API FieldDefinition query was not accessible with the current user permissions.',
        remediation:
          'Grant the audit user Tooling API access, or manually verify field history tracking in Setup → Object Manager for Account, Contact, Lead, Opportunity, Case, Contract, and User.',
      });
    }

    return { findings };
  }
}
