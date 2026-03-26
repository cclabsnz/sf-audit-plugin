import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body: string;
  NamespacePrefix: string | null;
}

const INHERITED_SHARING = /\binherited\s+sharing\b/i;
const WITHOUT_SHARING = /\bwithout\s+sharing\b/i;
const WITH_SHARING = /\bwith\s+sharing\b/i;
const CLASS_PATTERN = /\bclass\s+\w+/i;
const IS_TEST_CLASS = /@IsTest\b/i;

type SharingDeclaration = 'with' | 'without' | 'inherited' | 'none';

function getSharingDeclaration(body: string): SharingDeclaration | null {
  if (!CLASS_PATTERN.test(body)) {
    return null; // Not a class — skip interfaces, enums, etc.
  }
  if (WITH_SHARING.test(body)) return 'with';
  if (WITHOUT_SHARING.test(body)) return 'without';
  if (INHERITED_SHARING.test(body)) return 'inherited';
  return 'none';
}

export class ApexSharingCheck implements SecurityCheck {
  readonly id = 'apex-sharing';
  readonly name = 'Apex Sharing Declarations';
  readonly category = 'Code Security';
  readonly description = 'Classifies Apex classes by sharing declaration (with sharing, without sharing, inherited, omitted)';

  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    let apexBodies = ctx.cache.apexBodies;

    if (!apexBodies) {
      // Fall back to querying if cache not populated
      const records = await ctx.tooling.query<ApexClassRecord>(
        'SELECT Id, Name, Body, NamespacePrefix FROM ApexClass WHERE NamespacePrefix = null'
      );
      apexBodies = records.map((r) => ({ name: r.Name, body: r.Body }));
    }

    const withSharingClasses: string[] = [];
    const withoutSharingClasses: string[] = [];
    const inheritedSharingClasses: string[] = [];
    const noDeclarationClasses: string[] = [];

    for (const apexClass of apexBodies) {
      const body = apexClass.body ?? '';

      // Test classes run as sysadmin — sharing declarations are not applicable
      if (IS_TEST_CLASS.test(body)) continue;

      const declaration = getSharingDeclaration(body);

      if (declaration === null) continue; // Not a class definition

      switch (declaration) {
        case 'with':
          withSharingClasses.push(apexClass.name);
          break;
        case 'without':
          withoutSharingClasses.push(apexClass.name);
          break;
        case 'inherited':
          inheritedSharingClasses.push(apexClass.name);
          break;
        case 'none':
          noDeclarationClasses.push(apexClass.name);
          break;
      }
    }

    const total =
      withSharingClasses.length +
      withoutSharingClasses.length +
      inheritedSharingClasses.length +
      noDeclarationClasses.length;

    if (withoutSharingClasses.length > 0) {
      const count = withoutSharingClasses.length;
      findings.push({
        id: 'apex-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} Apex class(es) explicitly use "without sharing"`,
        detail: "Classes declared \"without sharing\" ignore the running user's record access and can access all data in the org.",
        remediation: 'Replace "without sharing" with "with sharing" or "inherited sharing" unless there is a documented business requirement.',
        affectedItems: withoutSharingClasses,
      });
    }

    if (noDeclarationClasses.length > 0) {
      const count = noDeclarationClasses.length;
      findings.push({
        id: 'apex-no-sharing-declaration',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count} Apex class(es) have no sharing declaration`,
        detail: "Apex classes without a sharing declaration default to \"without sharing\" behavior when called from a context that doesn't enforce sharing.",
        remediation: 'Add explicit sharing declarations to all Apex classes. Use "with sharing" as the default, or "inherited sharing" for utility classes.',
        affectedItems: noDeclarationClasses.slice(0, 20),
      });
    }

    findings.push({
      id: 'apex-sharing-summary',
      category: this.category,
      riskLevel: 'INFO',
      title: `Apex sharing analysis: ${withSharingClasses.length} with sharing, ${inheritedSharingClasses.length} inherited, ${withoutSharingClasses.length} without sharing, ${noDeclarationClasses.length} no declaration (${total} total)`,
      detail: `Summary of sharing declarations across ${total} custom Apex classes.`,
      remediation: 'Aim for all classes to use "with sharing" or "inherited sharing".',
    });

    return { findings };
  }
}
