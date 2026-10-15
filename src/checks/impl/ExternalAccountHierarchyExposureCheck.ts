import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { queryIfPresent } from '../support/missingObject.js';

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

function isMissingPrmField(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /No such column 'IsPrmSuperUser'/i.test(msg);
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

    // 1. Active users with Partner Super User access. User.IsPrmSuperUser only exists in orgs
    // with a partner (PRM) licence; there its absence means no super users. Any other error
    // propagates so the check reports inconclusive rather than clean.
    let superUsers: UserRecord[];
    try {
      superUsers = await ctx.soql.queryAll<UserRecord>(
        'SELECT Id, Username, IsActive, IsPrmSuperUser FROM User WHERE IsPrmSuperUser = true AND IsActive = true',
      );
    } catch (err) {
      if (!isMissingPrmField(err)) throw err;
      superUsers = [];
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
    const hierarchies = await queryIfPresent(() =>
      ctx.soql.queryAll<ExternalAccountHierarchyRecord>('SELECT Id, MasterLabel FROM ExternalAccountHierarchy'),
    );

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
