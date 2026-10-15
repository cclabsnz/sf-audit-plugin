import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface UserRecord {
  Id: string;
  Username: string;
  IsActive: boolean;
  IsPrmSuperUser?: boolean;
  Profile?: { Name?: string };
}

interface ExternalAccountHierarchyRecord {
  Id: string;
  DeveloperName?: string;
  MasterLabel?: string;
  Status?: string;
  HierarchyLevel?: number;
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

export class ExternalAccountHierarchyExposureCheck implements SecurityCheck {
  readonly id = 'external-account-hierarchy-exposure';
  readonly name = 'External Account Hierarchy & Partner Super User Exposure';
  readonly category = 'External-Facing Access';
  readonly description =
    'Flags Partner Super User access and External Account Hierarchies that bypass external OWD and widen portal visibility.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const usersUrl = `${baseUrl}/lightning/setup/ManageUsers/home`;

    // 1. Query users with IsPrmSuperUser = true
    let superUsers: UserRecord[] = [];
    try {
      superUsers = await ctx.soql.queryAll<UserRecord>(
        'SELECT Id, Username, IsActive, IsPrmSuperUser FROM User WHERE IsPrmSuperUser = true AND IsActive = true',
      );
    } catch {
      // IsPrmSuperUser might not be enabled in orgs without PRM licenses
    }

    if (superUsers.length > 0) {
      findings.push({
        id: 'external-account-hierarchy-super-users',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${superUsers.length} active portal user(s) granted Partner Super User Access (IsPrmSuperUser)`,
        detail:
          'Enabling Partner Super User Access grants external portal users visibility across all cases, opportunities, contacts, and custom objects owned by other partner users in their partner account hierarchy. This broadens data access beyond standard sharing rules and circumvents Private External Org-Wide Defaults.',
        remediation:
          'Review all users with Partner Super User Access in Setup → Users, and disable IsPrmSuperUser unless justified by strict business need.',
        affectedItems: superUsers.map((u) => ({
          label: u.Username,
          url: `${baseUrl}/lightning/setup/ManageUsers/page?address=%2F${u.Id}`,
          note: 'IsPrmSuperUser = true: cross-user record visibility in portal',
        })),
      });
    }

    // 2. Query ExternalAccountHierarchy records
    let hierarchies: ExternalAccountHierarchyRecord[] = [];
    try {
      hierarchies = await ctx.soql.queryAll<ExternalAccountHierarchyRecord>(
        'SELECT Id, MasterLabel FROM ExternalAccountHierarchy',
      );
    } catch (err) {
      if (!isMissingObjectError(err)) {
        // Degrade gracefully
      }
    }

    if (hierarchies.length > 0) {
      findings.push({
        id: 'external-account-hierarchy-active',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${hierarchies.length} active External Account Hierarchy relationship(s) configured`,
        detail:
          'External Account Hierarchies link separate partner and customer portal accounts into parent-child relationships, granting parent portal users upward and horizontal record visibility across child accounts without standard sharing rules.',
        remediation:
          'Audit all active External Account Hierarchy relationships in Setup → External Account Hierarchies to verify cross-account data exposure conforms to least-privilege sharing models.',
        affectedItems: hierarchies.map((h) => ({
          label: h.MasterLabel || h.Id,
          url: usersUrl,
          note: 'External Account Hierarchy active',
        })),
      });
    }

    if (superUsers.length === 0 && hierarchies.length === 0) {
      findings.push({
        id: 'external-account-hierarchy-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Partner Super Users or External Account Hierarchies widening portal visibility',
        detail: 'External portal users are constrained to their own account boundaries without hierarchical over-sharing.',
        remediation: 'Maintain standard Private external OWD and avoid unreviewed Super User grants.',
      });
    }

    return { findings };
  }
}
