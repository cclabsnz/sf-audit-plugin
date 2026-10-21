import type { AuditContext } from '@cclabsnz/sf-core';
import { FlowRepository } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { queryIfPresent } from '../support/missingObject.js';

interface ExternalServiceRegistrationRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  // The registration names its credential either by name (NamedCredential) or by reference.
  NamedCredential?: string | null;
  NamedCredentialReferenceId?: string | null;
}

/** Flow.Metadata is one row per Tooling query, so reads run concurrently but bounded. */
const METADATA_CONCURRENCY = 8;

// Patterns for hardcoded credentials / tokens in Flow formulas, headers, or parameters
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9_.-]{12,}/i,
  /Basic\s+[A-Za-z0-9+/=]{16,}/i,
  /(?:api[_-]?key|client[_-]?secret|auth[_-]?token|webhook[_-]?secret)\s*[:=]\s*['"][^'"]{8,}['"]/i,
  /https?:\/\/[^:]+:[^@]+@/i,
];

export class FlowHttpCalloutCredentialBypassCheck implements SecurityCheck {
  readonly id = 'flow-http-callout-credential-bypass';
  readonly name = 'Flow HTTP Callout Credential Bypass';
  readonly category = 'Integration Security';
  readonly description =
    'Detects declarative Flow HTTP callouts storing credentials in formulas or bypassing modern Named Credentials.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const externalServices = await queryIfPresent(() =>
      ctx.tooling.query<ExternalServiceRegistrationRecord>(
        'SELECT Id, DeveloperName, MasterLabel, NamedCredential, NamedCredentialReferenceId FROM ExternalServiceRegistration',
      ),
    );
    const uncredentialedServices = externalServices.filter(
      (s) => !(s.NamedCredential ?? '').trim() && !(s.NamedCredentialReferenceId ?? '').trim(),
    );

    // Credentials live in the flow definition (formulas, constants, text templates, action
    // inputs), which only Flow.Metadata carries. Every string in it is scanned.
    const repo = new FlowRepository(ctx.soql, ctx.tooling);
    const { versions } = FlowRepository.selectVersions(await repo.listDefinitions());
    const hardcodedSecretFlows: Array<{ id: string; apiName: string }> = [];
    let unread = 0;
    await mapWithConcurrency(versions, METADATA_CONCURRENCY, async (v) => {
      let metadata: unknown;
      try {
        metadata = await repo.fetchMetadata(v.id);
      } catch {
        unread++;
        return;
      }
      if (stringsIn(metadata).some((str) => SECRET_PATTERNS.some((p) => p.test(str)))) {
        hardcodedSecretFlows.push(v);
      }
    });
    hardcodedSecretFlows.sort((x, y) => x.apiName.localeCompare(y.apiName));

    if (hardcodedSecretFlows.length > 0) {
      findings.push({
        id: 'flow-http-callout-hardcoded-secret',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${hardcodedSecretFlows.length} Flow(s) contain hardcoded credentials or API keys in callout logic`,
        detail:
          'Flow HTTP Callout actions or formulas contain embedded bearer tokens, API keys, or basic authentication credentials. Storing credentials directly in declarative Flows bypasses Apex static analysis and exposes secrets to anyone who can view or export Flow definitions.',
        remediation:
          'Replace all hardcoded secrets in Flow formulas and HTTP Callout headers with modern Named Credentials and External Credentials with encrypted auth headers.',
        affectedItems: hardcodedSecretFlows.map((fl) => ({
          label: fl.apiName,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${fl.id}`,
          note: 'Contains embedded credential or API token',
        })),
      });
    }

    if (uncredentialedServices.length > 0) {
      findings.push({
        id: 'flow-http-callout-uncredentialed-endpoint',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${uncredentialedServices.length} External Service(s) configured without a Named Credential`,
        detail:
          'ExternalServiceRegistration records missing a designated Named Credential connect to remote endpoints without managed authentication and network controls, increasing exposure to rogue API endpoints and SSRF.',
        remediation:
          'Assign an approved Named Credential to every External Service Registration.',
        affectedItems: uncredentialedServices.map((s) => ({
          label: s.MasterLabel || s.DeveloperName,
          url: `${baseUrl}/lightning/setup/ExternalServices/home`,
          note: 'External Service lacks a Named Credential binding',
        })),
      });
    }

    if (unread > 0 && hardcodedSecretFlows.length === 0) {
      findings.push({
        id: 'flow-http-callout-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `${unread} of ${versions.length} active Flow definition(s) could not be read`,
        detail:
          'Flow metadata could not be retrieved for some active flows, so they were not scanned for embedded credentials. The flows that were read contained none.',
        remediation: 'Grant the audit user View Setup and Configuration and access to Flow metadata, then re-run.',
      });
    } else if (hardcodedSecretFlows.length === 0 && uncredentialedServices.length === 0) {
      findings.push({
        id: 'flow-http-callout-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Declarative Flow HTTP Callouts use proper Named Credentials without embedded secrets',
        detail: 'External services and declarative flows were inspected; no hardcoded API keys or uncredentialed external service endpoints detected.',
        remediation: 'Continue utilizing Named Credentials and External Credentials for all declarative HTTP integrations.',
      });
    }

    return { findings };
  }
}

/** Every string value anywhere in a parsed metadata tree. */
function stringsIn(node: unknown): string[] {
  if (typeof node === 'string') return [node];
  if (Array.isArray(node)) return node.flatMap(stringsIn);
  if (node && typeof node === 'object') return Object.values(node).flatMap(stringsIn);
  return [];
}

async function mapWithConcurrency<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) await fn(items[next++]);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
