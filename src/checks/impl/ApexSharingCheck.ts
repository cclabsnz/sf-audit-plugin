import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { ApexRepository, testApexPattern } from '@cclabsnz/sf-core';
import { apexApiVersions, apexCode, effectiveSharing, enteredOnlyThroughAura, omittedSharingEnforced } from '../support/apexAccess.js';

const IS_TEST_CLASS = /@IsTest\b/i;
// SBS-CPORTAL-001: @AuraEnabled and @RemoteAction expose a class to portal and community users;
// @RestResource exposes it to any API caller (spec RULE-005).
const IS_EXTERNALLY_EXPOSED = /@AuraEnabled\b|@RemoteAction\b|@RestResource\b/i;

export class ApexSharingCheck implements SecurityCheck {
  readonly id = 'apex-sharing';
  readonly name = 'Apex Sharing Declarations';
  readonly category = 'Code Security';
  readonly description = 'Classifies Apex classes by sharing declaration (with sharing, without sharing, inherited, omitted)';

  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const apexClassesUrl = `${baseUrl}/lightning/setup/ApexClasses/home`;

    let apexBodies = ctx.cache.apexBodies;

    if (!apexBodies) {
      // Fall back to querying if cache not populated
      const records = await new ApexRepository(ctx.tooling).listClasses({ excludeManaged: true });
      apexBodies = records.map((r) => ({ name: r.name, body: r.body ?? '' }));
    }

    const withSharingClasses: string[] = [];
    const withoutSharingClasses: string[] = [];
    const inheritedSharingClasses: string[] = [];
    const noDeclarationClasses: string[] = [];
    // No keyword, but compiled at API 67.0 or later: sharing is enforced by default (spec RULE-007).
    const defaultWithClasses: string[] = [];
    // SBS-CPORTAL-001: portal-exposed Apex without enforcement = IDOR risk
    const portalExposedWithoutSharing: string[] = [];
    const portalExposedNoDeclaration: string[] = [];

    const bodyByName = new Map(apexBodies.map((b) => [b.name.toLowerCase(), b.body ?? '']));
    const lookup = (n: string) => bodyByName.get(n.toLowerCase());
    const versions = await apexApiVersions(ctx);
    const versionOf = (n: string) => versions.get(n.toLowerCase());
    for (const apexClass of apexBodies) {
      const body = apexClass.body ?? '';

      const code = apexCode(body);
      // Test classes run as sysadmin — sharing declarations are not applicable
      if (testApexPattern(code, IS_TEST_CLASS)) continue;

      // Read from the class's own declaration, not any mention in the body (spec MN-002).
      // SYSTEM_MODE does not enter into it: it bypasses CRUD/FLS, not sharing (spec RULE-001).
      // A class with no keyword takes the sharing of the class it extends (spec MN-001).
      const declaration = effectiveSharing(apexClass.name, body, lookup);

      if (declaration === null) continue; // Not a class definition

      const isPortalExposed = testApexPattern(code, IS_EXTERNALLY_EXPOSED);

      switch (declaration) {
        case 'with':
          withSharingClasses.push(apexClass.name);
          break;
        case 'without':
          withoutSharingClasses.push(apexClass.name);
          if (isPortalExposed) portalExposedWithoutSharing.push(apexClass.name);
          break;
        case 'inherited':
          inheritedSharingClasses.push(apexClass.name);
          break;
        case 'none':
          if (omittedSharingEnforced(apexClass.name, body, lookup, versionOf)) {
            defaultWithClasses.push(apexClass.name);
            break;
          }
          noDeclarationClasses.push(apexClass.name);
          // An Aura/LWC call into a keyword-less class runs with sharing (spec RULE-008).
          if (isPortalExposed && !enteredOnlyThroughAura(body)) portalExposedNoDeclaration.push(apexClass.name);
          break;
      }
    }

    const total =
      withSharingClasses.length +
      withoutSharingClasses.length +
      inheritedSharingClasses.length +
      noDeclarationClasses.length +
      defaultWithClasses.length;

    // SBS-CPORTAL-001: portal-exposed classes with weak sharing declarations are the highest risk
    const allPortalRisk = [...new Set([...portalExposedWithoutSharing, ...portalExposedNoDeclaration])];
    if (allPortalRisk.length > 0) {
      findings.push({
        id: 'portal-exposed-apex-without-sharing',
        category: this.category,
        // CRITICAL only for an explicit "without sharing". A class with no declaration takes its
        // sharing from how it is entered, so it is a strong signal, not a confirmed bypass.
        riskLevel: portalExposedWithoutSharing.length > 0 ? 'CRITICAL' : 'HIGH',
        title: `${allPortalRisk.length} externally exposed Apex class(es) (@AuraEnabled/@RemoteAction/@RestResource) lack "with sharing": IDOR risk`,
        detail:
          'Classes with @AuraEnabled, @RemoteAction or @RestResource methods that use "without sharing" or have no sharing declaration execute without record-level access control. Attackers can supply arbitrary record IDs to read or manipulate data they should not access (IDOR). SBS-CPORTAL-001 requires server-side authorization for every record accessed via portal Apex.',
        remediation:
          'Add "with sharing" to all @AuraEnabled, @RemoteAction and @RestResource classes. Validate user ownership or sharing on every record accessed inside these methods.',
        affectedItems: allPortalRisk.map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: portalExposedWithoutSharing.includes(name)
            ? 'Uses explicit "without sharing": replace with "with sharing"'
            : 'No sharing declaration, entered through REST or remoting: add "with sharing"',
        })),
      });
    }

    if (withoutSharingClasses.length > 0) {
      const count = withoutSharingClasses.length;
      findings.push({
        id: 'apex-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} Apex class(es) explicitly use "without sharing"`,
        detail: "Classes declared \"without sharing\" ignore the running user's record access and can access all data in the org.",
        remediation: 'Replace "without sharing" with "with sharing" or "inherited sharing" unless there is a documented business requirement.',
        affectedItems: withoutSharingClasses.map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: 'Change to "with sharing" or "inherited sharing" and test thoroughly',
        })),
      });
    }

    if (noDeclarationClasses.length > 0) {
      const count = noDeclarationClasses.length;
      findings.push({
        id: 'apex-no-sharing-declaration',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count} Apex class(es) have no sharing declaration`,
        detail: "These classes declare no sharing keyword and are not shown to be saved at API 67.0 or later (with every keyword-less parent; a version that could not be read counts as older), so they run without sharing when called from a context that doesn't enforce sharing (an entry point such as REST or a Visualforce controller). From API 67.0 (Summer '26) an omitted keyword means with sharing, but only for classes saved at that version.",
        remediation: 'Add explicit sharing declarations to all Apex classes. Use "with sharing" as the default, or "inherited sharing" for utility classes. Raising a class to API 67.0 or later also makes an omitted keyword mean "with sharing", but test it first: queries and DML then run in user mode by default too.',
        affectedItems: noDeclarationClasses.slice(0, 20).map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: 'Add "with sharing" or "inherited sharing" declaration',
        })),
      });
    }

    findings.push({
      id: 'apex-sharing-summary',
      category: this.category,
      riskLevel: 'INFO',
      title: `Apex sharing analysis: ${withSharingClasses.length} with sharing, ${inheritedSharingClasses.length} inherited, ${withoutSharingClasses.length} without sharing, ${noDeclarationClasses.length} no declaration${defaultWithClasses.length > 0 ? `, ${defaultWithClasses.length} no declaration at API 67.0+ (with sharing by default)` : ''} (${total} total)`,
      detail: `Summary of sharing declarations across ${total} custom Apex classes.`,
      remediation: 'Aim for all classes to use "with sharing" or "inherited sharing".',
    });

    return { findings };
  }
}
