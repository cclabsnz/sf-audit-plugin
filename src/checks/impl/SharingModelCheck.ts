import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface EntityDefinitionRecord {
  QualifiedApiName: string;
  InternalSharingModel: string;
  ExternalSharingModel: string;
}

const OBJECTS_TO_CHECK = ['Account', 'Contact', 'Opportunity', 'Case', 'Lead'];
const PUBLIC_WRITE_MODELS = new Set(['ReadWrite', 'ReadWriteTransfer', 'FullAccess']);
const PUBLIC_READ_MODELS = new Set(['Read']);

export class SharingModelCheck implements SecurityCheck {
  readonly id = 'sharing-model';
  readonly name = 'Org-Wide Defaults (OWD) Sharing Model';
  readonly category = 'Data Access Control';
  readonly description =
    'Checks OWD sharing settings for Account, Contact, Opportunity, Case, and Lead — both internal and external (portal) sharing models';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const owdUrl = `${baseUrl}/lightning/setup/SecuritySharing/page`;

    const nameList = OBJECTS_TO_CHECK.map((n) => `'${n}'`).join(', ');
    let entities: EntityDefinitionRecord[];
    try {
      entities = await ctx.soql.queryAll<EntityDefinitionRecord>(
        `SELECT QualifiedApiName, InternalSharingModel, ExternalSharingModel
         FROM EntityDefinition
         WHERE QualifiedApiName IN (${nameList})`,
      );
    } catch {
      findings.push({
        id: 'sharing-model-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'OWD sharing settings could not be retrieved',
        detail:
          'The EntityDefinition SOQL query was not accessible. This may indicate the audit user lacks "View Setup and Configuration" permission.',
        remediation: 'Grant "View Setup and Configuration" to the audit user and re-run.',
      });
      return { findings };
    }

    const internalWriteObjects: Array<{ name: string; model: string }> = [];
    const externalWriteObjects: Array<{ name: string; model: string }> = [];
    const externalReadObjects: Array<{ name: string; model: string }> = [];
    const internalReadObjects: Array<{ name: string; model: string }> = [];

    for (const entity of entities) {
      const name = entity.QualifiedApiName;
      const internal = entity.InternalSharingModel;
      const external = entity.ExternalSharingModel;

      if (PUBLIC_WRITE_MODELS.has(internal)) {
        internalWriteObjects.push({ name, model: internal });
      } else if (PUBLIC_READ_MODELS.has(internal)) {
        internalReadObjects.push({ name, model: internal });
      }

      if (PUBLIC_WRITE_MODELS.has(external)) {
        externalWriteObjects.push({ name, model: external });
      } else if (PUBLIC_READ_MODELS.has(external)) {
        externalReadObjects.push({ name, model: external });
      }
    }

    let hasFindings = false;

    if (externalWriteObjects.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'sharing-model-external-write',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${externalWriteObjects.length} object(s) have Public Read/Write OWD for external/portal users`,
        detail:
          'An external OWD of Public Read/Write exposes all records to Experience Cloud portal users and guest users. Any low-trust or unauthenticated portal user can read and modify every record. This is a critical data exposure vector frequently overlooked when configuring portal sites — attackers who create or compromise a portal account gain unrestricted write access to the entire dataset.',
        remediation:
          'Set external OWD to Private for all sensitive objects immediately. Grant portal access via sharing sets, sharing rules, or Apex managed sharing — never via open OWD.',
        affectedItems: externalWriteObjects.map((o) => ({
          label: o.name,
          url: owdUrl,
          note: `External OWD: ${o.model} — immediate action required`,
        })),
      });
    }

    if (externalReadObjects.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'sharing-model-external-read',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${externalReadObjects.length} object(s) have Public Read OWD for external/portal users`,
        detail:
          'An external OWD of Public Read exposes all records to any Experience Cloud portal user. Attackers who create or compromise a portal account can enumerate the entire dataset for reconnaissance and data theft — even without write access, bulk record exposure violates data minimisation principles and enables targeted attacks.',
        remediation:
          'Set external OWD to Private and use sharing sets or sharing rules to grant portal users access only to their own records.',
        affectedItems: externalReadObjects.map((o) => ({
          label: o.name,
          url: owdUrl,
          note: `External OWD: ${o.model} — portal users can read all records`,
        })),
      });
    }

    if (internalWriteObjects.length > 0) {
      hasFindings = true;
      const riskLevel: 'HIGH' | 'MEDIUM' = internalWriteObjects.length >= 3 ? 'HIGH' : 'MEDIUM';
      findings.push({
        id: 'sharing-model-internal-write',
        category: this.category,
        riskLevel,
        title: `${internalWriteObjects.length} object(s) have Public Read/Write OWD for internal users`,
        detail:
          'An internal OWD of Public Read/Write means every authenticated user can read and modify all records regardless of record ownership. A compromised internal account, malicious insider, or over-permissioned integration user gains full access to the entire dataset. This undermines record-level access controls and violates least-privilege principles.',
        remediation:
          'Set OWD to Private or Public Read Only for sensitive objects. Use sharing rules, role hierarchy, or Apex managed sharing to grant specific access where needed.',
        affectedItems: internalWriteObjects.map((o) => ({
          label: o.name,
          url: owdUrl,
          note: `Internal OWD: ${o.model} — change to Private or Public Read Only`,
        })),
      });
    }

    if (internalReadObjects.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'sharing-model-internal-read',
        category: this.category,
        riskLevel: 'LOW',
        title: `${internalReadObjects.length} object(s) have Public Read OWD for internal users`,
        detail:
          'An internal OWD of Public Read means all authenticated users can view all records. While read-only access is less severe than write access, it may expose sensitive data to users who should not see all records (e.g., HR data visible to all sales reps).',
        remediation:
          'Review whether these objects contain sensitive data. If so, consider setting OWD to Private and creating sharing rules to grant access by role or territory.',
        affectedItems: internalReadObjects.map((o) => ({
          label: o.name,
          url: owdUrl,
          note: `Internal OWD: ${o.model} — all internal users can read all records`,
        })),
      });
    }

    if (!hasFindings) {
      findings.push({
        id: 'sharing-model-secure',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All checked objects have appropriately restrictive OWD settings',
        detail: `All ${OBJECTS_TO_CHECK.length} standard objects (${OBJECTS_TO_CHECK.join(', ')}) have Private or Controlled-by-Parent OWD for both internal and external users.`,
        remediation:
          'Continue monitoring OWD settings as new Experience Cloud sites and custom objects are added.',
      });
    }

    return { findings };
  }
}
