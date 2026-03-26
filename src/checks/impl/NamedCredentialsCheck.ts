import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NamedCredentialRecord {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
  Endpoint: string;
}

interface ApexClassRecord {
  Name: string;
  Body: string;
}

export class NamedCredentialsCheck implements SecurityCheck {
  readonly id = 'named-credentials';
  readonly name = 'Named Credentials';
  readonly category = 'External Connectivity';
  readonly description = 'Inventories Named Credentials and flags any not referenced in Apex code';

  readonly populatesCache = ['namedCredentialEndpoints'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/NamedCredential/page`;

    // Query named credentials using Tooling API
    const records = await ctx.tooling.query<NamedCredentialRecord>(
      'SELECT Id, MasterLabel, DeveloperName, Endpoint FROM NamedCredential'
    );

    const count = records.length;

    // Cache the endpoints for use by HardcodedCredentialsCheck
    ctx.cache.namedCredentialEndpoints = records.map((r) => r.Endpoint);

    if (count === 0) {
      findings.push({
        id: 'named-credentials-none',
        category: this.category,
        riskLevel: 'INFO',
        title: 'No named credentials configured',
        detail:
          'No named credentials are configured. If this org makes external callouts, consider using Named Credentials to avoid hardcoded endpoints.',
        remediation:
          'Configure Named Credentials for any external service integrations rather than hardcoding endpoints in Apex.',
      });
      return { findings, metrics: { namedCredentialsCount: 0, unusedNamedCredentialsCount: 0 } };
    }

    // Scan Apex code to find which named credentials are actually referenced
    // Named credentials are referenced as 'callout:DeveloperName' in Apex
    let apexBodies: Array<{ name: string; body: string }> = ctx.cache.apexBodies ?? [];

    if (apexBodies.length === 0) {
      try {
        const apexRecords = await ctx.tooling.query<ApexClassRecord>(
          'SELECT Name, Body FROM ApexClass WHERE NamespacePrefix = null'
        );
        apexBodies = apexRecords.map((r) => ({ name: r.Name, body: r.Body ?? '' }));
      } catch {
        // If we can't scan Apex, emit inventory only
        findings.push({
          id: 'named-credentials-inventory',
          category: this.category,
          riskLevel: 'INFO',
          title: `${count} named credential(s) configured`,
          detail: 'Named credentials provide a secure way to store endpoint URLs and authentication details for external callouts.',
          remediation: 'Periodically review named credentials to ensure endpoints are current and credentials remain valid.',
          affectedItems: records.map((r) => ({
            label: r.MasterLabel,
            url: setupUrl,
            note: r.Endpoint,
          })),
        });
        return { findings, metrics: { namedCredentialsCount: count, unusedNamedCredentialsCount: 0 } };
      }
    }

    const combinedApexSource = apexBodies.map((c) => c.body).join('\n');

    const unusedCredentials = records.filter((r) => {
      // Named credentials are referenced as callout:DeveloperName or callout:MasterLabel
      const refPatternDev = new RegExp(`callout:${r.DeveloperName}\\b`, 'i');
      const refPatternLabel = new RegExp(`callout:${r.MasterLabel.replace(/\s+/g, '_')}\\b`, 'i');
      return !refPatternDev.test(combinedApexSource) && !refPatternLabel.test(combinedApexSource);
    });

    const usedCredentials = records.filter((r) => !unusedCredentials.includes(r));

    // Inventory finding
    findings.push({
      id: 'named-credentials-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${count} named credential(s) configured (${usedCredentials.length} used, ${unusedCredentials.length} unused in Apex)`,
      detail: 'Named credentials provide a secure way to store endpoint URLs and authentication details for external callouts.',
      remediation: 'Periodically review named credentials to ensure endpoints are current and credentials remain valid.',
      affectedItems: records.map((r) => ({
        label: r.MasterLabel,
        url: setupUrl,
        note: r.Endpoint,
      })),
    });

    // Flag unused credentials
    if (unusedCredentials.length > 0) {
      findings.push({
        id: 'named-credentials-unused',
        category: this.category,
        riskLevel: 'LOW',
        title: `${unusedCredentials.length} named credential(s) are not referenced in any Apex class`,
        detail:
          'Named credentials with no Apex references may be stale configuration from removed integrations. Unused credentials still hold valid endpoint and authentication data.',
        remediation:
          'Review each unused named credential. If the integration it supports has been removed, delete the credential to reduce the attack surface.',
        affectedItems: unusedCredentials.map((r) => ({
          label: r.MasterLabel,
          url: setupUrl,
          note: `${r.Endpoint} — verify if still required, delete if orphaned`,
        })),
      });
    }

    return {
      findings,
      metrics: {
        namedCredentialsCount: count,
        unusedNamedCredentialsCount: unusedCredentials.length,
      },
    };
  }
}
