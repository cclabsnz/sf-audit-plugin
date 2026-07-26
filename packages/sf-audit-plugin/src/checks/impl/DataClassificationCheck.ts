import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FieldClassificationRecord {
  objectName: string;
  classifiedCount: number;
}

interface EncryptionKeyRecord {
  Id: string;
  DeveloperName: string;
}

// Key objects to check for data classification (SBS-DATA-001/002)
const CLASSIFICATION_OBJECTS = [
  'Account', 'Contact', 'Lead', 'Opportunity', 'Case', 'Contract', 'User',
];

export class DataClassificationCheck implements SecurityCheck {
  readonly id = 'data-classification';
  readonly name = 'Data Classification and Encryption';
  readonly category = 'Data Security';
  readonly description = 'SBS-DATA-001/002/003: checks Salesforce field data classification usage and Shield Platform Encryption';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const objectList = CLASSIFICATION_OBJECTS.map((o) => `'${o}'`).join(', ');

    // Q1 (Tooling API): count fields with a ComplianceGroup set per key object.
    // Salesforce Data Classification sets ComplianceGroup on FieldDefinition to mark fields
    // as PII, PCI, HIPAA, GDPR, etc. Objects with zero classified fields are uncovered.
    let classifiedMap = new Map<string, number>();
    let classificationQueryFailed = false;

    try {
      const classResult = await ctx.tooling.query<FieldClassificationRecord>(
        `SELECT EntityDefinition.QualifiedApiName objectName, COUNT(Id) classifiedCount
         FROM FieldDefinition
         WHERE EntityDefinition.QualifiedApiName IN (${objectList})
           AND ComplianceGroup != null
         GROUP BY EntityDefinition.QualifiedApiName`
      );
      for (const r of classResult) {
        classifiedMap.set(r.objectName, r.classifiedCount ?? 0);
      }
    } catch {
      classificationQueryFailed = true;
    }

    // Q2 (SOQL): check for Shield Platform Encryption keys.
    // EncryptionKey records indicate Shield is licensed and active.
    let encryptionEnabled = false;
    let encryptionKeyCount = 0;
    try {
      const encResult = await ctx.soql.query<EncryptionKeyRecord>(
        'SELECT Id, DeveloperName FROM EncryptionKey LIMIT 10'
      );
      encryptionKeyCount = encResult.records.length;
      encryptionEnabled = encryptionKeyCount > 0;
    } catch {
      // EncryptionKey inaccessible — Shield not licensed or no permission to read keys
    }

    // SBS-DATA-001/002: data classification coverage
    if (classificationQueryFailed) {
      findings.push({
        id: 'data-classification-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Data classification status could not be determined: Tooling API access needed',
        detail:
          'SBS-DATA-001 requires all data fields to be classified by sensitivity. SBS-DATA-002 requires PII fields to be explicitly identified. The Tooling API FieldDefinition query was not accessible with the current user permissions.',
        remediation:
          'Enable Tooling API access for the audit user, or manually review data classification in Setup → Data Management → Data Classification for Account, Contact, Lead, Opportunity, Case, Contract, and User.',
      });
    } else {
      const classifiedObjects = CLASSIFICATION_OBJECTS.filter((o) => (classifiedMap.get(o) ?? 0) > 0);
      const unclassifiedObjects = CLASSIFICATION_OBJECTS.filter((o) => (classifiedMap.get(o) ?? 0) === 0);
      const totalClassifiedFields = [...classifiedMap.values()].reduce((a, b) => a + b, 0);

      if (unclassifiedObjects.length === 0) {
        findings.push({
          id: 'data-classification-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: `Data classification configured on all ${CLASSIFICATION_OBJECTS.length} key objects: SBS-DATA-001/002`,
          detail: `SBS-DATA-001 requires data to be classified by sensitivity and SBS-DATA-002 requires PII to be identified. All checked objects have at least one classified field (total: ${totalClassifiedFields} classified fields across ${classifiedObjects.length} objects).`,
          remediation: 'Extend classification to any custom objects that store sensitive or personally identifiable data.',
        });
      } else {
        findings.push({
          id: 'data-classification-missing',
          category: this.category,
          riskLevel: unclassifiedObjects.length >= 4 ? 'HIGH' : 'MEDIUM',
          title: `${unclassifiedObjects.length} of ${CLASSIFICATION_OBJECTS.length} key object(s) have no data classification: SBS-DATA-001/002`,
          detail:
            `SBS-DATA-001 requires all data to be classified by sensitivity and SBS-DATA-002 requires PII to be identified. ${unclassifiedObjects.length} key object(s) have no fields with a Compliance Group set: ${unclassifiedObjects.join(', ')}. ${classifiedObjects.length > 0 ? `Objects with classification already configured: ${classifiedObjects.map((o) => `${o} (${classifiedMap.get(o)} field(s))`).join(', ')}.` : ''}`,
          remediation:
            'Enable and configure the Salesforce Data Classification feature in Setup → Data Management → Data Classification. Assign compliance groups (PII, PCI, HIPAA, GDPR, etc.) to sensitive fields on all objects that store personal or regulated data. Prioritise email, phone, address, financial, and health-related fields.',
          affectedItems: unclassifiedObjects.map((name) => ({
            label: name,
            url: `${baseUrl}/lightning/setup/ObjectManager/${name}/FieldsAndRelationships/view`,
            note: 'No fields classified: configure Compliance Group via Data Classification in Setup',
          })),
        });
      }
    }

    // SBS-DATA-003: encryption at rest
    if (encryptionEnabled) {
      findings.push({
        id: 'data-encryption-shield-active',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `Shield Platform Encryption active: ${encryptionKeyCount} encryption key(s) found (SBS-DATA-003)`,
        detail:
          `SBS-DATA-003 requires sensitive data to be encrypted at rest commensurate with its classification. ${encryptionKeyCount} Shield Platform Encryption key(s) are configured, indicating encryption-at-rest is in use.`,
        remediation:
          'Verify encryption is applied to all fields classified as sensitive or PII. Review the Encryption Statistics page in Setup → Security → Platform Encryption to confirm field-level coverage.',
      });
    } else {
      findings.push({
        id: 'data-encryption-not-detected',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: 'Shield Platform Encryption not detected: SBS-DATA-003',
        detail:
          'SBS-DATA-003 requires data at rest to be encrypted in line with its assigned classification. No Shield Platform Encryption keys were found, indicating either Shield is not licensed or encryption has not been configured for this org.',
        remediation:
          'Evaluate Salesforce Shield Platform Encryption for fields classified as sensitive or PII. If Shield is not available in your edition, document the compensating control (e.g., Classic Encryption for specific fields, or infrastructure-level disk encryption), and assess whether it meets the intent of SBS-DATA-003.',
      });
    }

    return { findings };
  }
}
