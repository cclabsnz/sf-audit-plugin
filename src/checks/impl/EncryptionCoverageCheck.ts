import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ClassifiedFieldRec {
  EntityDefinition?: { QualifiedApiName?: string } | null;
  QualifiedApiName: string;
}
interface DescribeResult {
  fields?: Array<{ name: string; encrypted?: boolean }>;
}

const MAX_OBJECTS = 25; // cap describe calls

// FieldDefinition must be filtered by entity ("a filter on a reified column is required"), so the
// scan covers these key standard objects, the same set data-classification checks.
const SCANNED_OBJECTS = ['Account', 'Contact', 'Lead', 'Opportunity', 'Case', 'Contract', 'User', 'Individual'];

/**
 * Cross-references data classification against ACTUAL field encryption. `data-
 * classification` confirms Shield is licensed and that fields are classified;
 * this check answers the next question: are the fields marked sensitive (PII/PHI
 * via ComplianceGroup) actually encrypted at rest? Classified-but-plaintext
 * fields are the gap that matters for a health/PII org — the data is labelled
 * sensitive yet stored in the clear.
 */
export class EncryptionCoverageCheck implements SecurityCheck {
  readonly id = 'encryption-coverage';
  readonly name = 'Encryption Coverage for Sensitive Fields';
  readonly category = 'Data Security';
  readonly description =
    'Flags fields classified as sensitive (PII/PHI via ComplianceGroup) that are not encrypted at rest with Shield Platform Encryption';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // 1. Sensitive fields = those with a ComplianceGroup (PII/PCI/HIPAA/GDPR/...).
    let classified: ClassifiedFieldRec[];
    try {
      classified = await ctx.tooling.query<ClassifiedFieldRec>(
        `SELECT EntityDefinition.QualifiedApiName, QualifiedApiName
         FROM FieldDefinition
         WHERE EntityDefinition.QualifiedApiName IN (${SCANNED_OBJECTS.map((o) => `'${o}'`).join(', ')})
           AND ComplianceGroup != null`,
      );
    } catch (err) {
      findings.push(
        this.inconclusive(
          'Classified fields could not be queried',
          `The Tooling API FieldDefinition query failed: ${err instanceof Error ? err.message : String(err)}`,
        ),
      );
      return { findings };
    }

    const fieldsByObj = new Map<string, Set<string>>();
    for (const c of classified) {
      const obj = c.EntityDefinition?.QualifiedApiName;
      if (!obj || !c.QualifiedApiName) continue;
      const set = fieldsByObj.get(obj) ?? new Set<string>();
      set.add(c.QualifiedApiName);
      fieldsByObj.set(obj, set);
    }

    if (fieldsByObj.size === 0) {
      findings.push({
        id: 'encryption-coverage-no-classification',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No fields are classified as sensitive on the key standard objects',
        detail: `No fields on ${SCANNED_OBJECTS.join(', ')} carry a ComplianceGroup (data classification), so encryption coverage cannot be assessed against a sensitivity baseline. Custom objects are not scanned. Classification is the prerequisite — see the data-classification check.`,
        remediation: 'Classify PII/PHI fields (Setup → Data Classification) first, then encrypt the sensitive ones with Shield Platform Encryption.',
      });
      return { findings };
    }

    // 2. For each classified object, describe it and read per-field encryption.
    const unencrypted: string[] = [];
    let describedAny = false;
    for (const [obj, fields] of [...fieldsByObj.entries()].slice(0, MAX_OBJECTS)) {
      let desc: DescribeResult;
      try {
        desc = await ctx.rest.get<DescribeResult>(`/sobjects/${obj}/describe`);
      } catch {
        continue;
      }
      if (!desc.fields) continue;
      describedAny = true;
      const encryptedNames = new Set(desc.fields.filter((f) => f.encrypted).map((f) => f.name));
      for (const field of fields) {
        if (!encryptedNames.has(field)) unencrypted.push(`${obj}.${field}`);
      }
    }

    if (!describedAny) {
      findings.push(
        this.inconclusive(
          'Object describes were not accessible, so field encryption could not be confirmed',
          'The audit user could not describe the classified objects, so per-field encryption is unknown.',
        ),
      );
      return { findings };
    }

    if (unencrypted.length > 0) {
      findings.push({
        id: 'encryption-coverage-unencrypted-sensitive',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unencrypted.length} field(s) classified sensitive but NOT encrypted at rest`,
        detail:
          'These fields are labelled sensitive (PII/PHI/PCI via a ComplianceGroup) yet are stored in plaintext — Shield Platform Encryption is not applied. For a health/PII org this is the gap that matters: the data is known-sensitive but unprotected at rest, exposed to anyone who can read the field, and to at-rest/export exposure.',
        remediation:
          'Enable Shield Platform Encryption on these fields (Setup → Platform Encryption → Encryption Policy). Prefer probabilistic encryption unless a field must be filtered/sorted; if deterministic is required, treat it as weaker and document the tradeoff. Re-encrypt existing data after enabling.',
        affectedItems: unencrypted.slice(0, 50).map((f) => ({ label: f, url: `${baseUrl}/lightning/setup/PlatformEncryptionPolicy/home` })),
      });
    } else {
      findings.push({
        id: 'encryption-coverage-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All classified sensitive fields checked are encrypted at rest',
        detail: `Every classified field found across ${Math.min(fieldsByObj.size, MAX_OBJECTS)} object(s) is encrypted with Shield Platform Encryption. Scanned: ${SCANNED_OBJECTS.join(', ')}; custom objects are not scanned.`,
        remediation: 'Keep encryption policy in sync as new sensitive fields are added and classified.',
      });
    }

    return { findings };
  }

  private inconclusive(what: string, detail: string): Finding {
    return {
      id: 'encryption-coverage-inconclusive',
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what}`,
      detail: `${detail} Encryption coverage is unassessed, not clean.`,
      remediation:
        'Check the error above. If it is an access error, confirm the audit user has API Enabled and View Setup and Configuration, then re-run.',
    };
  }
}
