import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface EntityRecord {
  QualifiedApiName: string;
  NamespacePrefix?: string | null;
}

interface FieldRecord {
  EntityDefinition?: { QualifiedApiName?: string } | null;
  QualifiedApiName: string;
  DataType: string | null;
  NamespacePrefix?: string | null;
}

// Words in a field name that say the value is a secret. Bare "key" counts only after a qualifier
// (api, private, access, client, signing, secret, encryption): alone it names prefixes, record keys
// and flags far more often than credentials.
const SECRET_WORDS = new Set(['password', 'passwd', 'pwd', 'passphrase', 'secret', 'token', 'apikey', 'privatekey', 'accesskey', 'credential', 'credentials', 'bearer']);
const KEY_QUALIFIERS = new Set(['api', 'private', 'access', 'client', 'signing', 'secret', 'encryption']);
// A name ending in one of these describes a secret (where it lives, what it is called), not the secret.
const DESCRIBES_ONLY = new Set(['endpoint', 'url', 'uri', 'name', 'label', 'type', 'count', 'length', 'date', 'expiry', 'expiration', 'id']);

/** Whether a field's own name (no namespace, no __c) says it holds a secret. */
export function namesSecret(qualifiedApiName: string): boolean {
  const base = qualifiedApiName.replace(/^[A-Za-z0-9]+__(?=.+__c$)/, '').replace(/__c$/, '');
  const words = base.split(/_+|(?<=[a-z0-9])(?=[A-Z])/).map((w) => w.toLowerCase()).filter(Boolean);
  if (words.length === 0 || DESCRIBES_ONLY.has(words[words.length - 1])) return false;
  // The name of a Named Credential is the recommended thing to store, not a secret.
  if (words.some((w, i) => w === 'named' && words[i + 1]?.startsWith('credential')) || words.includes('namedcredential')) return false;
  return words.some((w, i) => SECRET_WORDS.has(w) || (w === 'key' && i > 0 && KEY_QUALIFIERS.has(words[i - 1])));
}

/** Plain or long text: a value someone could paste a secret into. Encrypted text is not plain. */
function isPlainText(dataType: string | null): boolean {
  return dataType != null && /text/i.test(dataType) && !/encrypt/i.test(dataType);
}

// FieldDefinition is read for a set of entities per query, this many at a time.
const FIELD_BATCH = 50;

/**
 * Secrets stored in custom settings or custom metadata types. Their records are readable through
 * the API and Apex by users with access to the type, so a password or token kept there is exposed
 * in a way a Named Credential's secret is not.
 *
 * Evidence is the field, not the type's name: a text field on a custom setting or custom metadata
 * type whose name says it holds a password, secret, token or key. The record values are never read,
 * so a match is a field to review, not a secret found. Managed-package components are listed apart:
 * a protected one is not readable from this org, and only the vendor can change it.
 */
export class CustomSettingsCheck implements SecurityCheck {
  readonly id = 'custom-settings';
  readonly name = 'Custom Settings and Credentials';
  readonly category = 'Code Security';
  readonly description =
    'Flags text fields on custom settings and custom metadata types whose names say they hold a password, secret, token or key';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let settings: EntityRecord[];
    try {
      settings = await ctx.tooling.query<EntityRecord>(
        'SELECT QualifiedApiName, NamespacePrefix FROM EntityDefinition WHERE IsCustomSetting = true',
      );
    } catch (err) {
      findings.push(this.inconclusive('Custom settings could not be listed', err));
      return { findings };
    }

    // Custom metadata types are read separately: a failure here still leaves custom settings read.
    let mdt: EntityRecord[] = [];
    let mdtError: string | null = null;
    try {
      const rows = await ctx.tooling.query<EntityRecord>(
        "SELECT QualifiedApiName, NamespacePrefix FROM EntityDefinition WHERE QualifiedApiName LIKE '%__mdt'",
      );
      // '_' is a LIKE wildcard, so confirm the suffix.
      mdt = rows.filter((r) => r.QualifiedApiName.endsWith('__mdt'));
    } catch (err) {
      mdtError = err instanceof Error ? err.message : String(err);
    }

    const entities = [...settings, ...mdt];
    let fields: FieldRecord[] = [];
    try {
      for (let i = 0; i < entities.length; i += FIELD_BATCH) {
        const names = entities.slice(i, i + FIELD_BATCH).map((e) => `'${e.QualifiedApiName}'`).join(', ');
        fields.push(
          ...(await ctx.tooling.query<FieldRecord>(
            `SELECT EntityDefinition.QualifiedApiName, QualifiedApiName, DataType, NamespacePrefix FROM FieldDefinition WHERE EntityDefinition.QualifiedApiName IN (${names})`,
          )),
        );
      }
    } catch (err) {
      findings.push(this.inconclusive('Custom setting and custom metadata fields could not be read', err));
      return { findings };
    }

    // A field is the vendor's when the field itself carries a namespace; an org's own field on a
    // managed type is the org's to fix.
    const managed = (f: FieldRecord) => Boolean(f.NamespacePrefix);
    const isMdt = (obj: string) => obj.endsWith('__mdt');
    const matches = fields.filter((f) => f.EntityDefinition?.QualifiedApiName && namesSecret(f.QualifiedApiName) && isPlainText(f.DataType));
    const mdtNote = mdtError ? ` Custom metadata types could not be listed (${mdtError}), so only custom settings were read.` : '';
    const scope = `${settings.length} custom setting(s) and ${mdt.length} custom metadata type(s)`;

    const item = (f: FieldRecord) => {
      const obj = f.EntityDefinition!.QualifiedApiName!;
      return {
        label: `${obj}.${f.QualifiedApiName}`,
        url: `${baseUrl}/lightning/setup/${isMdt(obj) ? 'CustomMetadata' : 'CustomSettings'}/home`,
        note: managed(f)
          ? `${f.DataType}; managed package: ask the vendor whether the type is protected and how the secret is stored`
          : `${f.DataType}; check whether records hold a secret`,
      };
    };
    const own = matches.filter((f) => !managed(f));
    const vendor = matches.filter(managed);

    if (own.length > 0) {
      findings.push({
        id: 'custom-settings-credentials',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${own.length} custom setting or custom metadata field(s) are named for a password, secret, token or key`,
        detail:
          `These plain-text fields on ${scope} are named as if they hold a secret. Their records can be read through the API by users with access to the type, so a secret stored there is exposed. Field values were not read: confirm what each holds.${mdtNote}`,
        remediation:
          'For each field, check whether its records hold a live secret. Move any that do to a Named Credential with an External Credential, rotate the secret, and clear the field.',
        affectedItems: own.map(item),
      });
    }
    // A vendor's field is reported apart and feeds no attack chain: whether it is readable depends
    // on the type's visibility, which this check does not read, and only the vendor can change it.
    if (vendor.length > 0) {
      findings.push({
        id: 'custom-settings-credentials-managed',
        category: this.category,
        riskLevel: 'LOW',
        title: `${vendor.length} managed package field(s) on custom settings or custom metadata are named for a secret`,
        detail: `These plain-text fields belong to installed packages and are named as if they hold a secret. A protected type is not readable from this org; a public one is. Field values were not read.${mdtNote}`,
        remediation: 'Ask each vendor whether the type is protected and how the secret is stored and rotated.',
        affectedItems: vendor.map(item),
      });
    }
    if (matches.length === 0) {
      findings.push({
        id: 'custom-settings-clean',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No custom setting or custom metadata field is named for a secret',
        detail: `Read the fields of ${scope}; no plain-text field is named for a password, secret, token or key. Field values were not read.${mdtNote}`,
        remediation: 'Keep secrets in Named Credentials and External Credentials, not in custom settings or custom metadata.',
      });
    }

    return { findings };
  }

  private inconclusive(what: string, err: unknown): Finding {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      id: 'custom-settings-inconclusive',
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: what,
      detail: `The audit user could not read custom setting or custom metadata definitions. The org returned: ${msg}`,
      remediation:
        'If the error is an access error, grant the audit user View Setup and Configuration (see PERMISSIONS.md) and re-run. Otherwise the area is unassessed, not clean.',
    };
  }
}
