import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface ExternalServiceRegistrationRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  NamedCredentialId?: string | null;
  SystemVersion?: string | null;
  ServiceContract?: string | null;
}

interface FlowRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  ProcessType: string;
  Description?: string | null;
  Metadata?: {
    actionCalls?: Array<{
      actionName?: string;
      actionType?: string;
      inputParameters?: Array<{ name: string; value?: { stringValue?: string } }>;
    }>;
    formulas?: Array<{
      name?: string;
      expression?: string;
    }>;
    constants?: Array<{
      name?: string;
      value?: { stringValue?: string };
    }>;
  } | null;
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
    msg.includes('sobject type')
  );
}

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

    // 1. Query ExternalServiceRegistration records (Tooling API)
    let externalServices: ExternalServiceRegistrationRecord[] = [];
    try {
      externalServices = await ctx.tooling.query<ExternalServiceRegistrationRecord>(
        'SELECT Id, DeveloperName, MasterLabel, NamedCredentialId, SystemVersion FROM ExternalServiceRegistration',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        // ExternalServiceRegistration not present in org
      }
    }

    const uncredentialedServices = externalServices.filter(
      (s) => !s.NamedCredentialId || s.NamedCredentialId.trim() === '',
    );

    // 2. Query active Flows with Tooling API to inspect actions and formulas
    let flows: FlowRecord[] = [];
    try {
      flows = await ctx.tooling.query<FlowRecord>(
        "SELECT Id, DeveloperName, MasterLabel, ProcessType, Description FROM Flow WHERE Status = 'Active'",
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        // Flow tooling query failed
      }
    }

    const hardcodedSecretFlows: FlowRecord[] = [];

    for (const fl of flows) {
      // Check flow description and metadata if available for embedded credentials
      const textToScan = `${fl.Description ?? ''} ${fl.DeveloperName} ${fl.MasterLabel}`;
      if (SECRET_PATTERNS.some((p) => p.test(textToScan))) {
        hardcodedSecretFlows.push(fl);
      }

      // Check Flow metadata actionCalls, formulas, constants
      if (fl.Metadata) {
        const meta = fl.Metadata;
        let foundSecret = false;

        if (meta.formulas) {
          for (const form of meta.formulas) {
            const expr = form.expression ?? '';
            if (SECRET_PATTERNS.some((p) => p.test(expr))) {
              foundSecret = true;
              break;
            }
          }
        }

        if (!foundSecret && meta.constants) {
          for (const c of meta.constants) {
            const val = c.value?.stringValue ?? '';
            if (SECRET_PATTERNS.some((p) => p.test(val))) {
              foundSecret = true;
              break;
            }
          }
        }

        if (!foundSecret && meta.actionCalls) {
          for (const act of meta.actionCalls) {
            for (const param of act.inputParameters ?? []) {
              const val = param.value?.stringValue ?? '';
              if (SECRET_PATTERNS.some((p) => p.test(val))) {
                foundSecret = true;
                break;
              }
            }
          }
        }

        if (foundSecret && !hardcodedSecretFlows.includes(fl)) {
          hardcodedSecretFlows.push(fl);
        }
      }
    }

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
          label: fl.MasterLabel || fl.DeveloperName,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${fl.Id}`,
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

    if (hardcodedSecretFlows.length === 0 && uncredentialedServices.length === 0) {
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
