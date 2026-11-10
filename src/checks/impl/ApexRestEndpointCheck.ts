import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { apexApiVersions, declaresWithoutSharing, effectiveSharing, omittedSharingEnforced } from '../support/apexAccess.js';

const REST_RESOURCE_RE = /@RestResource\s*\(\s*urlMapping\s*=/i;
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

    // A class with no keyword takes its parent's sharing (spec MN-001).
    const bodyByName = new Map(apexBodies.map((b) => [b.name.toLowerCase(), b.body ?? '']));
    const lookup = (n: string) => bodyByName.get(n.toLowerCase());
    const sharingOf = (c: { name: string; body: string }) => effectiveSharing(c.name, c.body, lookup);

    // Flag endpoints declared (or inheriting) without sharing — REST callers bypass record-level access
    // Read from code, not text: "without sharing" in a comment or string runs nothing. An inner class
    // declared without sharing counts, as in the guest Apex check: the endpoint can call into it.
    const withoutSharing = restClasses.filter((c) => declaresWithoutSharing(c.body) || sharingOf(c) === 'without');
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

    // Flag endpoints with no sharing declaration at all, unless compiled at API 67.0 or later,
    // where an omitted keyword means with sharing (spec RULE-007).
    const undeclared = restClasses.filter((c) => !withoutSharing.includes(c) && sharingOf(c) === 'none');
    const versions = undeclared.length > 0 ? await apexApiVersions(ctx) : new Map<string, number>();
    const noSharingDeclaration = undeclared.filter(
      (c) => !omittedSharingEnforced(c.name, c.body, lookup, (n) => versions.get(n.toLowerCase())),
    );
    if (noSharingDeclaration.length > 0) {
      findings.push({
        id: 'apex-rest-no-sharing-declaration',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${noSharingDeclaration.length} REST endpoint class(es) have no sharing declaration`,
        detail:
          `These REST endpoint classes declare no sharing keyword and are not shown to be saved at API 67.0 or later (with every keyword-less parent; a version that could not be read counts as older). A REST call enters the class directly, so it runs without sharing, and every caller reaches records beyond its own sharing. From API 67.0 (Summer '26) an omitted keyword means with sharing, but only for classes saved at that version. Explicit "with sharing" is required for predictable, secure behaviour.`,
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
