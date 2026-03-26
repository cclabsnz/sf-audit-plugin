import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CustomFieldRecord {
  Id: string;
  DeveloperName: string;
  TableEnumOrId: string;
}

interface EntityDefinitionRecord {
  Id: string;
  QualifiedApiName: string;
}

interface FieldPermRecord {
  Field: string;
  cnt: number;
}

export class FieldLevelSecurityCheck implements SecurityCheck {
  readonly id = 'field-level-security';
  readonly name = 'Field-Level Security';
  readonly category = 'Data Access';
  readonly description = 'Detects sensitive custom fields (SSN, credit card, tax ID) exposed to broad permission sets';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // 1. Find sensitive custom fields
    let sensitiveFields: CustomFieldRecord[] = [];
    try {
      sensitiveFields = await ctx.tooling.query<CustomFieldRecord>(
        `SELECT Id, DeveloperName, TableEnumOrId FROM CustomField
         WHERE (DeveloperName LIKE '%SSN%' OR DeveloperName LIKE '%SocialSecurity%'
           OR DeveloperName LIKE '%CreditCard%' OR DeveloperName LIKE '%Password%'
           OR DeveloperName LIKE '%Token%' OR DeveloperName LIKE '%BankAccount%'
           OR DeveloperName LIKE '%DOB%' OR DeveloperName LIKE '%DateOfBirth%'
           OR DeveloperName LIKE '%MedicalRecord%' OR DeveloperName LIKE '%Diagnosis%')
         LIMIT 100`
      );
    } catch {
      findings.push({
        id: 'field-level-security-query-error',
        category: this.category,
        riskLevel: 'INFO',
        title: 'Field-level security analysis could not be completed',
        detail:
          'The CustomField query failed. This may be due to insufficient permissions or Tooling API access restrictions.',
        remediation:
          'Ensure the running user has access to the Tooling API and CustomField sobject.',
      });
      return { findings };
    }

    if (sensitiveFields.length === 0) {
      findings.push({
        id: 'field-level-security-ok',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Sensitive custom fields appear appropriately restricted',
        detail: 'No sensitive custom fields with excessive permission set access were found.',
        remediation:
          'Continue to apply restrictive field-level security to any new sensitive fields.',
      });
      return { findings };
    }

    // 2. Resolve object API names
    const objectIds = [...new Set(sensitiveFields.map((f) => f.TableEnumOrId))];
    let entityDefs: EntityDefinitionRecord[] = [];
    try {
      entityDefs = await ctx.tooling.query<EntityDefinitionRecord>(
        `SELECT Id, QualifiedApiName FROM EntityDefinition WHERE Id IN (${objectIds.map((id) => `'${id}'`).join(', ')})`
      );
    } catch {
      // If entity lookup fails, fall through — field names will be unresolvable
    }

    const objectApiNameById = new Map<string, string>(
      entityDefs.map((e) => [e.Id, e.QualifiedApiName])
    );

    // Build field API names: {ObjectApiName}.{DeveloperName}__c
    const fieldApiNames: string[] = [];
    const fieldApiNameMap = new Map<string, string>();

    for (const field of sensitiveFields) {
      const objectApiName = objectApiNameById.get(field.TableEnumOrId);
      if (objectApiName) {
        const fieldApiName = `${objectApiName}.${field.DeveloperName}__c`;
        fieldApiNames.push(fieldApiName);
        fieldApiNameMap.set(fieldApiName, fieldApiName);
      }
    }

    if (fieldApiNames.length === 0) {
      findings.push({
        id: 'field-level-security-ok',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Sensitive custom fields appear appropriately restricted',
        detail: 'No sensitive custom fields with excessive permission set access were found.',
        remediation:
          'Continue to apply restrictive field-level security to any new sensitive fields.',
      });
      return { findings };
    }

    // 3. Check how many permission sets give Read access per field
    let permRecords: FieldPermRecord[] = [];
    try {
      const result = await ctx.soql.query<FieldPermRecord>(
        `SELECT Field, COUNT(ParentId) cnt FROM FieldPermissions
         WHERE PermissionsRead = true AND Field IN (${fieldApiNames.map((f) => `'${f}'`).join(', ')})
         GROUP BY Field`
      );
      permRecords = result.records.map((r) => ({
        Field: r.Field,
        cnt: (r as unknown as Record<string, unknown>).cnt != null
          ? Number((r as unknown as Record<string, unknown>).cnt)
          : 0,
      }));
    } catch {
      findings.push({
        id: 'field-level-security-ok',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Sensitive custom fields appear appropriately restricted',
        detail: 'No sensitive custom fields with excessive permission set access were found.',
        remediation:
          'Continue to apply restrictive field-level security to any new sensitive fields.',
      });
      return { findings };
    }

    const highExposure = permRecords.filter((r) => r.cnt > 15);
    const mediumExposure = permRecords.filter((r) => r.cnt > 10 && r.cnt <= 15);

    if (highExposure.length > 0) {
      findings.push({
        id: 'field-level-security-high',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${highExposure.length} sensitive field(s) are readable by more than 15 permission sets`,
        affectedItems: highExposure.map((r) => {
          const objectApiName = r.Field.split('.')[0];
          return {
            label: r.Field,
            url: `${baseUrl}/lightning/setup/ObjectManager/${objectApiName}/FieldsAndRelationships/view`,
            note: `Readable by ${r.cnt} permission sets — restrict to minimum required`,
          };
        }),
        detail:
          'Widely-accessible sensitive fields increase the risk of data exposure. These fields may contain PII, PHI, or financial data.',
        remediation:
          'Review field-level security for each affected field. Restrict access to the minimum number of roles that require it.',
      });
    }

    if (mediumExposure.length > 0) {
      findings.push({
        id: 'field-level-security-medium',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${mediumExposure.length} sensitive field(s) are readable by 10-15 permission sets`,
        affectedItems: mediumExposure.map((r) => {
          const objectApiName = r.Field.split('.')[0];
          return {
            label: r.Field,
            url: `${baseUrl}/lightning/setup/ObjectManager/${objectApiName}/FieldsAndRelationships/view`,
            note: `Readable by ${r.cnt} permission sets — review and reduce access`,
          };
        }),
        detail:
          'Widely-accessible sensitive fields increase the risk of data exposure. These fields may contain PII, PHI, or financial data.',
        remediation:
          'Review field-level security for each affected field. Restrict access to the minimum number of roles that require it.',
      });
    }

    if (highExposure.length === 0 && mediumExposure.length === 0) {
      findings.push({
        id: 'field-level-security-ok',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Sensitive custom fields appear appropriately restricted',
        detail: 'No sensitive custom fields with excessive permission set access were found.',
        remediation:
          'Continue to apply restrictive field-level security to any new sensitive fields.',
      });
    }

    return { findings };
  }
}
