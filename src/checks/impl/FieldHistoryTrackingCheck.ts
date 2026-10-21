import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface TrackedFieldRecord {
  EntityDefinition?: { QualifiedApiName?: string } | null;
  QualifiedApiName: string;
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
      // Tooling API: the tracked fields on each sensitive object, counted here. FieldDefinition
      // supports no aggregates (its Id is not aggregatable), so COUNT/GROUP BY is rejected.
      // Objects with zero tracked fields are absent from the result — those are violations.
      const results = await ctx.tooling.query<TrackedFieldRecord>(
        `SELECT EntityDefinition.QualifiedApiName, QualifiedApiName
         FROM FieldDefinition
         WHERE EntityDefinition.QualifiedApiName IN (${objectList})
           AND IsFieldHistoryTracked = true`
      );

      const trackedMap = new Map<string, number>();
      for (const r of results) {
        const obj = r.EntityDefinition?.QualifiedApiName;
        if (obj) trackedMap.set(obj, (trackedMap.get(obj) ?? 0) + 1);
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
        // Missing history limits investigation; it exposes nothing. RULE-078.
        riskLevel: withoutTracking.length >= 3 ? 'MEDIUM' : 'LOW',
        title: `${withoutTracking.length} sensitive object(s) have no field history tracking (investigation gap): SBS-DATA-004`,
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
    } catch (err) {
      findings.push({
        id: 'field-history-tracking-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Field history tracking status could not be determined',
        detail:
          `SBS-DATA-004 requires field history tracking on sensitive objects. The Tooling API FieldDefinition query failed, so tracking is unassessed, not absent: ${err instanceof Error ? err.message : String(err)}`,
        remediation:
          'Check the error above. If it is an access error, confirm the audit user has API Enabled and View Setup and Configuration; otherwise verify field history tracking manually in Setup → Object Manager for Account, Contact, Lead, Opportunity, Case, Contract, and User.',
      });
    }

    return { findings };
  }
}
