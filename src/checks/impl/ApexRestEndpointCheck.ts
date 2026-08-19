import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

const REST_RESOURCE_RE = /@RestResource\s*\(\s*urlMapping\s*=/i;
const WITHOUT_SHARING_RE = /\bwithout\s+sharing\b/i;
const NO_SHARING_DECLARED_RE = /\b(with|without|inherited)\s+sharing\b/i;
const IS_TEST_RE = /@IsTest\b/i;

export class ApexRestEndpointCheck implements SecurityCheck {
  readonly id = 'apex-rest-endpoint';
  readonly name = 'Apex REST Endpoint Security';
  readonly category = 'Code Security';
  readonly description = 'Flags @RestResource Apex classes that run without sharing, exposing records to REST callers without record-level access control';

  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const apexClassesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ApexClasses/home`;
    const apexBodies = ctx.cache.apexBodies ?? [];

    if (apexBodies.length === 0) {
      findings.push({
        id: 'apex-rest-no-bodies',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Apex class bodies not available: REST endpoint check skipped',
        detail: 'Apex bodies were not cached. Ensure HardcodedCredentialsCheck runs before this check.',
        remediation: 'Verify registry ordering.',
      });
      return { findings };
    }

    const restClasses = apexBodies.filter(
      ({ body }) => body && !IS_TEST_RE.test(body) && REST_RESOURCE_RE.test(body)
    );

    if (restClasses.length === 0) {
      findings.push({
        id: 'apex-rest-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No custom @RestResource Apex endpoints found',
        detail: 'No Apex classes with the @RestResource annotation were found in the org namespace.',
        remediation: 'Continue monitoring as new Apex code is developed.',
      });
      return { findings };
    }

    // Always emit an inventory of all REST endpoints
    findings.push({
      id: 'apex-rest-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${restClasses.length} custom Apex REST endpoint(s) found`,
      detail: 'Apex classes with @RestResource expose custom REST APIs. These should be reviewed to ensure they enforce authentication, sharing, and field-level security appropriate to the data they expose.',
      remediation: 'Review each REST endpoint: confirm it uses "with sharing", validates the caller, and applies field-level security before returning data.',
      affectedItems: restClasses.map(({ name }) => ({
        label: name,
        url: apexClassesUrl,
        note: 'Custom REST endpoint: review access controls',
      })),
    });

    // Flag endpoints declared without sharing — REST callers bypass record-level access
    const withoutSharing = restClasses.filter(({ body }) => WITHOUT_SHARING_RE.test(body));
    if (withoutSharing.length > 0) {
      findings.push({
        id: 'apex-rest-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${withoutSharing.length} REST endpoint class(es) declared "without sharing"`,
        detail:
          `Apex REST endpoints declared "without sharing" execute with elevated system privileges. Any authenticated (or, if the endpoint is exposed via a Community, unauthenticated) caller can retrieve or modify records regardless of the running user's sharing rules. This is a common vector for horizontal privilege escalation in Salesforce integrations.`,
        remediation:
          'Change declarations to "with sharing" so that record-level access is enforced for REST callers. Where system-level access is genuinely required (e.g. an integration service account), document the justification and ensure the endpoint is not accessible to end-user profiles.',
        affectedItems: withoutSharing.map(({ name }) => ({
          label: name,
          url: apexClassesUrl,
          note: '"without sharing" REST endpoint: callers bypass record sharing rules',
        })),
      });
    }

    // Flag endpoints with no sharing declaration at all (inherits from caller — unpredictable)
    const noSharingDeclaration = restClasses.filter(
      ({ body }) => !WITHOUT_SHARING_RE.test(body) && !NO_SHARING_DECLARED_RE.test(body)
    );
    if (noSharingDeclaration.length > 0) {
      findings.push({
        id: 'apex-rest-no-sharing-declaration',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${noSharingDeclaration.length} REST endpoint class(es) have no sharing declaration`,
        detail:
          `Apex classes with no sharing declaration inherit sharing mode from their caller, which is non-deterministic for REST API calls. In REST API contexts the caller is typically the integration user, whose sharing context may be broader than intended. Explicit "with sharing" is required for predictable, secure behaviour.`,
        remediation:
          'Add "with sharing" to all @RestResource classes to make sharing enforcement explicit and predictable.',
        affectedItems: noSharingDeclaration.map(({ name }) => ({
          label: name,
          url: apexClassesUrl,
          note: 'No sharing declaration: add "with sharing" explicitly',
        })),
      });
    }

    return { findings };
  }
}
