import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface TenantSecretRecord {
  Id: string;
  Status: string;
  Type?: string | null;
  Version?: number | null;
  CreatedDate: string;
  LastModifiedDate?: string | null;
}

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type') ||
    msg.includes('tenantsecret')
  );
}

export class ShieldTenantSecretLifecycleCheck implements SecurityCheck {
  readonly id = 'shield-tenant-secret-lifecycle';
  readonly name = 'Shield Platform Encryption Tenant Secret Lifecycle';
  readonly category = 'Data Security';
  readonly description =
    'Monitors Shield TenantSecret rotation frequency (>365 days) and destroyed key status for cryptographic compliance.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const keyMgmtUrl = `${baseUrl}/lightning/setup/PlatformEncryptionKeyManagement/home`;

    let secrets: TenantSecretRecord[] = [];
    try {
      secrets = await ctx.soql.queryAll<TenantSecretRecord>(
        'SELECT Id, Status, Type, Version, CreatedDate FROM TenantSecret',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'shield-tenant-secret-not-enabled',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'Shield Platform Encryption is not enabled or TenantSecret is not accessible',
          detail: 'TenantSecret object is not available; Shield Platform Encryption is not licensed or enabled.',
          remediation: 'No action required if Shield Platform Encryption is not in use.',
        });
        return { findings };
      }
      findings.push({
        id: 'shield-tenant-secret-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'TenantSecret could not be queried',
        detail: `Failed to query TenantSecret: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "Manage Encryption Keys" or "View Setup and Configuration".',
      });
      return { findings };
    }

    if (secrets.length === 0) {
      findings.push({
        id: 'shield-tenant-secret-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active Shield TenantSecret keys generated',
        detail: 'Zero TenantSecret records were returned.',
        remediation: 'Generate tenant encryption secrets if Shield Platform Encryption is enabled.',
      });
      return { findings };
    }

    const now = Date.now();
    const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

    const activeSecrets = secrets.filter(
      (s) => s.Status.toLowerCase() === 'active',
    );

    const unrotatedSecrets: TenantSecretRecord[] = [];

    for (const secret of activeSecrets) {
      const createdTime = new Date(secret.CreatedDate).getTime();
      if (now - createdTime > ONE_YEAR_MS) {
        unrotatedSecrets.push(secret);
      }
    }

    if (unrotatedSecrets.length > 0) {
      findings.push({
        id: 'shield-tenant-secret-unrotated',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unrotatedSecrets.length} active Shield Tenant Secret(s) have not been rotated in >365 days`,
        detail:
          'Active Shield tenant encryption keys (Data, SearchIndex, EventBus) have exceeded the 365-day rotation window. Cryptographic key lifecycle standards (ISO/IEC 27001:2022 A.8.24, NZISM 17.2, HISO 10029) require cryptographic keys to be rotated at least annually to minimize key exposure and compromise blast radius.',
        remediation:
          'Generate a new Tenant Secret in Setup → Platform Encryption → Key Management and re-encrypt affected archive data if required by corporate compliance policies.',
        affectedItems: unrotatedSecrets.map((s) => ({
          label: `Type: ${s.Type || 'Data'}, Version: ${s.Version ?? 'N/A'}`,
          url: keyMgmtUrl,
          note: `Created on ${new Date(s.CreatedDate).toISOString().slice(0, 10)} (>365 days active)`,
        })),
      });
    } else {
      findings.push({
        id: 'shield-tenant-secret-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Active Shield Tenant Secrets are rotated within cryptographic lifecycle standards',
        detail: `${activeSecrets.length} active Tenant Secret(s) verified; all active keys were created or rotated within the last 365 days.`,
        remediation: 'Continue regular annual tenant secret key rotation.',
      });
    }

    return { findings };
  }
}
