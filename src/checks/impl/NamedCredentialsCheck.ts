import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NamedCredentialRecord {
  Id: string;
  MasterLabel: string;
  Endpoint: string;
}

export class NamedCredentialsCheck implements SecurityCheck {
  readonly id = 'named-credentials';
  readonly name = 'Named Credentials';
  readonly category = 'External Connectivity';

  readonly populatesCache = ['namedCredentialEndpoints'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Query named credentials using Tooling API
    const records = await ctx.tooling.query<NamedCredentialRecord>(
      'SELECT Id, MasterLabel, Endpoint FROM NamedCredential'
    );

    const count = records.length;

    // Cache the endpoints for use by HardcodedCredentialsCheck
    ctx.cache.namedCredentialEndpoints = records.map((r) => r.Endpoint);

    // Always emit an INFO finding (inventory)
    const affectedItems = records.length > 0
      ? records.map((r) => `${r.MasterLabel}: ${r.Endpoint}`)
      : undefined;

    findings.push({
      id: 'named-credentials-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${count} named credential(s) configured`,
      detail:
        count > 0
          ? 'Named credentials provide a secure way to store endpoint URLs and authentication details for external callouts.'
          : 'No named credentials are configured. If this org makes external callouts, consider using Named Credentials to avoid hardcoded endpoints.',
      remediation:
        count > 0
          ? 'Periodically review named credentials to ensure endpoints are current and credentials remain valid.'
          : 'Configure Named Credentials for any external service integrations rather than hardcoding endpoints in Apex.',
      affectedItems,
    });

    return {
      findings,
      metrics: {
        namedCredentialsCount: count,
      },
    };
  }
}
