import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PermissionSetRecord { Id: string; Name: string; }

// Standard Salesforce built-in profiles present in every org — excluded from custom profile counts.
// Profile SOQL does not expose an IsCustom field; this list covers the known standard set.
const STANDARD_PROFILE_NAMES = [
  'System Administrator',
  'Standard User',
  'Read Only',
  'Solution Manager',
  'Marketing User',
  'Contract Manager',
  'Standard Platform User',
  'Standard Platform One App User',
  'Chatter Free User',
  'Chatter External User',
  'Chatter Moderator User',
  'High Volume Customer Portal User',
  'Authenticated Website',
  'Customer Portal Manager Standard',
  'Partner App Subscription User',
  'Analytics Cloud Explorer User',
  'Identity User',
  'Work.com Only User',
  'Force.com - App Subscription User',
  'Force.com - One App User',
  'Force.com - Free User',
  'Guest User',
  'External Apps Login User',
  'External Identity User',
  'Minimum Access - Salesforce',
];

export class PermissionsCheck implements SecurityCheck {
  readonly id = 'permissions';
  readonly name = 'Permissions';
  readonly category = 'Permissions';
  readonly description = 'Reports unassigned permission sets and high profile counts that increase the attack surface';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Custom permission sets only: IsCustom = true excludes profile-owned and Salesforce system-managed sets
    const psCountResult = await ctx.soql.query<{ expr0: number }>(
      'SELECT COUNT() FROM PermissionSet WHERE IsCustom = true'
    );
    const permissionSetCount = psCountResult.totalSize;

    const psRisk = permissionSetCount > 100 ? 'HIGH' : permissionSetCount > 50 ? 'MEDIUM' : 'LOW';
    findings.push({
      id: 'permissions-set-count',
      category: this.category,
      riskLevel: psRisk,
      title: `${permissionSetCount} custom permission sets in use`,
      detail: 'A large number of permission sets increases administrative complexity and makes it harder to audit access effectively.',
      remediation: 'Review and consolidate permission sets. Excessive numbers increase administrative complexity and expand the attack surface.',
    });

    // Unassigned custom permission sets — exclude direct assignments AND membership in a permission set group
    const unassignedResult = await ctx.soql.query<PermissionSetRecord>(
      'SELECT Id, Name FROM PermissionSet WHERE IsCustom = true AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetAssignment) AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetGroupComponent)'
    );
    const unassignedSets = unassignedResult.records;
    const unassignedCount = unassignedSets.length;

    if (unassignedCount > 0) {
      findings.push({
        id: 'permissions-unassigned-sets',
        category: this.category,
        riskLevel: 'LOW',
        title: `${unassignedCount} permission set(s) are defined but never assigned`,
        detail: 'Permission sets that are defined but never assigned to any user (directly or via a permission set group) represent configuration bloat and may indicate outdated or orphaned access configurations.',
        remediation: 'Unused permission sets should be reviewed and deleted to reduce configuration bloat.',
        affectedItems: unassignedSets.map((r) => ({
          label: r.Name,
          url: `${baseUrl}/${r.Id}`,
        })),
      });
    }

    // Custom profile count: exclude managed-package profiles (NamespacePrefix = null) and known standard Salesforce profiles
    const standardProfileList = STANDARD_PROFILE_NAMES.map((n) => `'${n}'`).join(', ');
    const profileCountResult = await ctx.soql.query<{ expr0: number }>(
      `SELECT COUNT() FROM Profile WHERE NamespacePrefix = null AND Name NOT IN (${standardProfileList})`
    );
    const profileCount = profileCountResult.totalSize;

    if (profileCount > 30) {
      findings.push({
        id: 'permissions-high-profile-count',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${profileCount} custom profiles exist in this org`,
        detail: 'A high number of custom profiles increases the complexity of access management and makes it harder to maintain a clear security model.',
        remediation: 'Consider migrating access control from profiles to permission sets for more granular and auditable access management.',
      });
    }

    return {
      findings,
      metrics: {
        permissionSetCount,
        profileCount,
      },
    };
  }
}
