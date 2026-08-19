import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface LabelRecord {
  Name: string;
  Value: string;
}

// Label names that suggest credential storage
const SENSITIVE_NAME_RE =
  /api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passphrase|private[_-]?key|credential|client[_-]?secret|bearer|webhook[_-]?secret/i;

// Value patterns that look like secrets (long base64/hex, Bearer tokens, etc.)
const SECRET_VALUE_RE =
  /^(?:Bearer\s+[A-Za-z0-9+/=_-]{20,}|[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{40,}={0,2}|sk_[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35})/;

export class CustomLabelsCredentialCheck implements SecurityCheck {
  readonly id = 'custom-labels-credential';
  readonly name = 'Custom Labels Credential Exposure';
  readonly category = 'Secrets Management';
  readonly description =
    'Scans Custom Labels for API keys, tokens, and credentials. Labels are globally readable by all authenticated users via {!$Label.X} merge fields';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ExternalStrings/home`;

    let labels: LabelRecord[];
    try {
      labels = await ctx.tooling.query<LabelRecord>(
        `SELECT Name, Value FROM ExternalString WHERE NamespacePrefix = null LIMIT 500`,
      );
    } catch {
      findings.push({
        id: 'custom-labels-credential-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Custom Labels could not be queried: credential scan skipped',
        detail:
          'The Tooling API ExternalString query was not accessible. This may indicate the audit user lacks Tooling API access.',
        remediation: 'Grant Tooling API access to the audit user and re-run.',
      });
      return { findings };
    }

    if (labels.length === 0) {
      findings.push({
        id: 'custom-labels-credential-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No custom labels found in org namespace',
        detail: 'No custom labels were found in the org namespace.',
        remediation: 'Continue using Named Credentials and Custom Metadata (protected) for secrets storage.',
      });
      return { findings };
    }

    const nameMatches: LabelRecord[] = [];
    const valueMatches: LabelRecord[] = [];

    for (const label of labels) {
      const value = label.Value ?? '';
      if (SENSITIVE_NAME_RE.test(label.Name)) {
        nameMatches.push(label);
      } else if (SECRET_VALUE_RE.test(value.trim())) {
        valueMatches.push(label);
      }
    }

    if (nameMatches.length > 0) {
      findings.push({
        id: 'custom-labels-credential-name-match',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${nameMatches.length} Custom Label(s) have names suggesting credential storage`,
        detail:
          `Custom Labels with names like "ApiKey", "ClientSecret", or "AuthToken" strongly suggest they store sensitive credentials. This is a critical misconfiguration: Custom Labels are globally readable by every authenticated Salesforce user via the \`{!$Label.X}\` merge field in Visualforce pages, Flows, and Apex. Any user who can query the Tooling API or view source markup containing the merge field can read the label value, including attacker accounts, compromised users, and over-permissioned portal users. Unlike Named Credentials or Protected Custom Metadata, Custom Labels have no access control.`,
        remediation:
          'Migrate these credentials to Named Credentials or Protected Custom Metadata (visibility: "Protected"). Named Credentials encrypt stored values and provide managed authentication. Protected Custom Metadata is only accessible from the managed package, not from arbitrary user queries.',
        affectedItems: nameMatches.map((l) => ({
          label: l.Name,
          url: setupUrl,
          note: `Name indicates credential: migrate to Named Credential or Protected Custom Metadata`,
        })),
      });
    }

    if (valueMatches.length > 0) {
      findings.push({
        id: 'custom-labels-credential-value-match',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${valueMatches.length} Custom Label(s) contain values matching known secret patterns`,
        detail:
          `The values of these Custom Labels match patterns for API keys (AWS AKIA*, Google AIza*, Stripe sk_*, hex/base64 tokens, Bearer tokens). These are globally readable by all authenticated users. Even if the label name is innocuous, storing secrets in Custom Labels violates secrets management best practices and can lead to credential theft by any user with org access.`,
        remediation:
          'Rotate any exposed credentials immediately. Migrate storage to Named Credentials or Protected Custom Metadata. Audit all code referencing these labels to understand the blast radius if credentials are already compromised.',
        affectedItems: valueMatches.map((l) => ({
          label: l.Name,
          url: setupUrl,
          note: `Value matches secret pattern: rotate credential and migrate storage`,
        })),
      });
    }

    if (nameMatches.length === 0 && valueMatches.length === 0) {
      findings.push({
        id: 'custom-labels-credential-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${labels.length} Custom Label(s) scanned: no obvious credential patterns found`,
        detail: `All ${labels.length} custom labels were scanned for name and value patterns indicating credential storage. No obvious secrets were found. Note: custom labels with obfuscated names or non-standard encoding may not be detected.`,
        remediation:
          'Maintain the practice of using Named Credentials or Protected Custom Metadata for all secrets. Periodically review Custom Labels for new entries that may inadvertently store sensitive values.',
      });
    }

    return { findings };
  }
}
