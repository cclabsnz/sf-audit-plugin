import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { ApexRepository } from '@cclabsnz/sf-core';
import { referencesCallout } from '../../lib/apexRefs.js';

interface NamedCredentialRecord {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
  // Nullable: modern External Credential-backed entries carry no endpoint URL.
  Endpoint: string | null;
  // PrincipalType: 'Anonymous' | 'NamedUser' | 'PerUser'
  // AuthTokenEndpointUrl is present only for OAuth-type credentials
  PrincipalType: string | null;
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
    const setupUrl = `${baseUrl}/lightning/setup/NamedCredential/home`;

    // Single Tooling query — PrincipalType lets us flag anonymous (no-auth) credentials
    const records = await ctx.tooling.query<NamedCredentialRecord>(
      'SELECT Id, MasterLabel, DeveloperName, Endpoint, PrincipalType FROM NamedCredential'
    );

    const count = records.length;

    // Cache the endpoints for use by HardcodedCredentialsCheck
    ctx.cache.namedCredentialEndpoints = records.map((r) => r.Endpoint).filter((e): e is string => !!e);

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
    // Whether the unused analysis has a basis. False only when the Apex read failed, which is
    // not the same as finding no references — hence a flag rather than an empty-set default.
    let apexScanned = true;

    // Endpoint is nullable for External Credential-backed entries. Interpolating it directly put
    // the literal "null" into advice shown to an operator.
    const endpointNote = (endpoint: string | null, advice: string): string =>
      `${endpoint ?? '(no endpoint — External Credential)'}: ${advice}`;

    if (apexBodies.length === 0) {
      try {
        const apexRecords = await new ApexRepository(ctx.tooling).listClasses({ excludeManaged: true });
        apexBodies = apexRecords.map((r) => ({ name: r.name, body: r.body ?? '' }));
      } catch {
        // Losing the Apex scan costs the unused analysis and nothing else. Returning here also
        // discarded the HTTP-endpoint and anonymous-principal findings, which are derived purely
        // from the credential records already in hand — including a HIGH finding for plaintext
        // HTTP that was fully established. Carry on with what the records support.
        apexScanned = false;
      }
    }

    const combinedApexSource = apexBodies.map((c) => c.body).join('\n');

    const unusedCredentials = apexScanned
      ? records.filter((r) => {
          // Named credentials are referenced as callout:DeveloperName or callout:MasterLabel
          // Literal search, not a pattern built from the credential's own name: MasterLabel is free
          // text from Setup, and a bracket in it used to crash the check while a quantifier quietly
          // matched the wrong thing.
          return (
            !referencesCallout(combinedApexSource, r.DeveloperName) &&
            !referencesCallout(combinedApexSource, r.MasterLabel.replace(/\s+/g, '_'))
          );
        })
      : [];

    const usedCredentials = apexScanned ? records.filter((r) => !unusedCredentials.includes(r)) : [];

    // Inventory finding
    findings.push({
      id: 'named-credentials-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: apexScanned
        ? `${count} named credential(s) configured (${usedCredentials.length} used, ${unusedCredentials.length} unused in Apex)`
        : `${count} named credential(s) configured`,
      detail: 'Named credentials provide a secure way to store endpoint URLs and authentication details for external callouts.',
      remediation: 'Periodically review named credentials to ensure endpoints are current and credentials remain valid.',
      affectedItems: records.map((r) => ({
        label: r.MasterLabel,
        url: setupUrl,
        note: r.Endpoint ?? '(no endpoint — External Credential)',
      })),
    });

    if (!apexScanned) {
      findings.push({
        id: 'named-credentials-unused-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Apex could not be scanned: named credentials were not checked for references',
        detail:
          'Listing Apex classes through the Tooling API failed, so which credentials are referenced by code is unestablished. Absence of an "unused credentials" finding below therefore means the analysis did not run, not that every credential is in use. The endpoint and principal-type findings are unaffected: both derive from the credential records, which were read successfully.',
        remediation:
          'Grant the audit user Tooling API access to ApexClass and re-run to get the unused-credential analysis.',
      });
    }

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
          note: endpointNote(r.Endpoint, 'verify if still required, delete if orphaned'),
        })),
      });
    }

    // SBS-INT-003: flag plaintext HTTP endpoints — credentials transmitted unencrypted in transit.
    const httpEndpoints = records.filter((r) => r.Endpoint?.startsWith('http://') ?? false);
    if (httpEndpoints.length > 0) {
      findings.push({
        id: 'named-credentials-http-endpoint',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${httpEndpoints.length} named credential(s) use plaintext HTTP endpoints`,
        detail:
          'Named credentials pointing to http:// endpoints transmit authentication tokens and data over an unencrypted channel, exposing them to interception. SBS-INT-003 requires inventory and justification of all named credential endpoints.',
        remediation:
          'Update each credential to use an https:// endpoint. If the target service does not support HTTPS, escalate to the vendor.',
        affectedItems: httpEndpoints.map((r) => ({
          label: r.MasterLabel,
          url: setupUrl,
          note: endpointNote(r.Endpoint, 'migrate to HTTPS'),
        })),
      });
    }

    // Flag anonymous (no-auth) named credentials: PrincipalType = 'Anonymous' means no credentials
    // are sent to the endpoint, which may indicate misconfiguration for authenticated services.
    const anonymousCreds = records.filter((r) => r.PrincipalType === 'Anonymous');
    if (anonymousCreds.length > 0) {
      findings.push({
        id: 'named-credentials-anonymous',
        category: this.category,
        riskLevel: 'LOW',
        title: `${anonymousCreds.length} named credential(s) use anonymous (no-auth) principal type`,
        detail:
          'Named credentials with PrincipalType "Anonymous" send no authentication to the external endpoint. This is acceptable for public APIs but should be reviewed to confirm no sensitive data is exchanged without authentication.',
        remediation:
          'Confirm that anonymous named credentials only point to fully public APIs. If any exchange sensitive data, configure Named User or Per-User OAuth authentication.',
        affectedItems: anonymousCreds.map((r) => ({
          label: r.MasterLabel,
          url: setupUrl,
          note: endpointNote(r.Endpoint, 'verify that no authentication is required'),
        })),
      });
    }

    return {
      findings,
      metrics: {
        namedCredentialsCount: count,
        // Omitted when the Apex scan failed: zero would be read as "none are unused", which was
        // never established.
        ...(apexScanned ? { unusedNamedCredentialsCount: unusedCredentials.length } : {}),
      },
    };
  }
}
