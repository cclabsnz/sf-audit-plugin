import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface DelegateGroupRec {
  Id: string;
  DeveloperName: string;
}

/**
 * Surfaces impersonation / delegated-administration paths that bypass a user's
 * own credentials:
 *   - Delegated Administration groups (`DelegateGroup`): members can manage users
 *     and assign permissions within a scope — a lateral-movement / priv-esc path
 *     that admin-focused monitoring often misses.
 *   - "Administrators Can Log In as Any User" (org Login Access Policy): when on,
 *     any admin can impersonate any user and read all their data with no consent.
 *     This toggle is not cleanly API-exposed, so it is raised as an advisory.
 */
export class LoginAccessPolicyCheck implements SecurityCheck {
  readonly id = 'login-access-policy';
  readonly name = 'Login-As & Delegated Administration';
  readonly category = 'Access Control';
  readonly description =
    'Flags delegated-administration groups and the org login-as policy, which allow user impersonation and scoped admin escalation that bypass normal credentials';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let groups: DelegateGroupRec[];
    try {
      groups = await ctx.soql.queryAll<DelegateGroupRec>('SELECT Id, DeveloperName FROM DelegateGroup');
    } catch {
      findings.push({
        id: 'login-access-policy-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Delegated administration could not be queried (insufficient access)',
        detail: 'DelegateGroup was not accessible, so delegated-admin escalation paths could not be evaluated.',
        remediation: 'Grant the audit user View Setup and Configuration, then re-run. Also manually verify Setup → Login Access Policies.',
      });
      return { findings };
    }

    if (groups.length > 0) {
      findings.push({
        id: 'login-access-policy-delegated-admins',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${groups.length} delegated administration group(s) configured`,
        detail:
          'Delegated administration groups let non-system-administrators manage users, reset passwords, and assign permission sets within a scope. Membership and the assignable permission sets are a privilege-escalation and lateral-movement path that is easy to overlook because these users are not full admins.',
        remediation:
          'Review each delegated group in Setup → Delegated Administration: confirm the delegated users are trusted, the manageable roles/objects are minimal, and the assignable permission sets do not include privileged permissions. Remove unused groups.',
        affectedItems: groups.slice(0, 30).map((g) => ({
          label: g.DeveloperName,
          url: `${baseUrl}/lightning/setup/DelegateGroups/home`,
        })),
      });
    } else {
      findings.push({
        id: 'login-access-policy-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No delegated administration groups configured',
        detail: 'No DelegateGroup records exist, so there is no delegated-admin escalation surface.',
        remediation: 'If delegated administration is introduced, scope each group minimally and review assignable permission sets.',
      });
    }

    await this.addLoginAsPolicyFinding(ctx, findings);
    return { findings };
  }

  /**
   * "Administrators Can Log In as Any User". Read authoritatively from
   * SecuritySettings metadata when a Metadata client is available; otherwise fall
   * back to a manual-verification advisory.
   */
  private async addLoginAsPolicyFinding(ctx: AuditContext, findings: Finding[]): Promise<void> {
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/LoginAccessPolicies/home`;

    if (ctx.metadata) {
      let ss: { enableAdminLoginAsAnyUser?: boolean } | null = null;
      try {
        ss = await ctx.metadata.read<{ enableAdminLoginAsAnyUser?: boolean }>('SecuritySettings', 'Security');
      } catch {
        ss = null;
      }
      if (ss && typeof ss.enableAdminLoginAsAnyUser === 'boolean') {
        if (ss.enableAdminLoginAsAnyUser) {
          findings.push({
            id: 'login-access-policy-login-as-enabled',
            category: this.category,
            riskLevel: 'HIGH',
            title: '"Administrators Can Log In as Any User" is ENABLED',
            detail:
              'The org policy "Administrators Can Log In as Any User" is enabled (confirmed from SecuritySettings). Any administrator can impersonate any user — including reading all of their records — with no per-session consent from that user, and the impersonation is easy to miss in monitoring.',
            remediation:
              'Disable "Administrators Can Log In as Any User" in Setup → Login Access Policies unless there is a documented support requirement. Require users to grant time-boxed login access instead, and alert on LoginAs events via Event Monitoring.',
            affectedItems: [{ label: 'Login Access Policies', url: setupUrl }],
          });
        } else {
          findings.push({
            id: 'login-access-policy-login-as-disabled',
            category: this.category,
            riskLevel: 'LOW',
            passed: true,
            title: '"Administrators Can Log In as Any User" is disabled',
            detail: 'SecuritySettings confirms administrators cannot log in as arbitrary users without their consent.',
            remediation: 'Keep this disabled; grant login access per-user and time-boxed when support needs it.',
          });
        }
        return;
      }
    }

    // No Metadata client, or the field was not present — advisory fallback.
    findings.push({
      id: 'login-access-policy-login-as-advisory',
      category: this.category,
      riskLevel: 'INFO',
      title: 'Verify the "Administrators Can Log In as Any User" policy manually',
      detail:
        'When "Administrators Can Log In as Any User" is enabled (Setup → Login Access Policies), any administrator can impersonate any user and access all of their data with no per-session consent. This run could not read SecuritySettings, so the policy must be confirmed manually.',
      remediation:
        'In Setup → Login Access Policies, disable "Administrators Can Log In as Any User" unless there is a documented support need, and require users to grant time-boxed login access instead.',
      affectedItems: [{ label: 'Login Access Policies', url: setupUrl }],
    });
  }
}
