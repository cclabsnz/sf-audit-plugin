import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { RiskLevel } from '@cclabsnz/sf-core';

interface ToxicCombo {
  id: string;
  label: string;
  /** All of these effective-permission keys must be present for the combo to fire. */
  perms: string[];
  risk: RiskLevel;
  why: string;
  fix: string;
}

// Combinations that, held by a single user, enable self-escalation, fraud, or
// undetectable abuse — even when each permission on its own looks acceptable.
const COMBOS: ToxicCombo[] = [
  {
    id: 'self-escalation',
    label: 'Manage Users + Assign Permission Sets',
    perms: ['ManageUsers', 'AssignPermissionSets'],
    risk: 'CRITICAL',
    why: 'The user can create/modify accounts and grant permission sets, so they can grant themselves (or a confederate) any access in the org: a self-service path to full admin.',
    fix: 'Split these duties across different roles. A user who assigns permission sets should not also administer users.',
  },
  {
    id: 'code-and-data',
    label: 'Author Apex + Modify All Data',
    perms: ['AuthorApex', 'ModifyAllData'],
    risk: 'CRITICAL',
    why: 'The user can deploy Apex that runs without sharing AND already has unrestricted data access: enabling code-driven mass exfiltration or tampering that bypasses every control.',
    fix: 'Remove Modify All Data from developers, or Author Apex from data-privileged users. Use separate sandbox/deploy identities for code.',
  },
  {
    id: 'grant-self-data',
    label: 'Assign Permission Sets + View All Data',
    perms: ['AssignPermissionSets', 'ViewAllData'],
    risk: 'HIGH',
    why: 'The user can read all data and grant access. They can escalate their own or others\' visibility silently.',
    fix: 'Separate permission-set administration from broad data-visibility roles.',
  },
  {
    id: 'identity-takeover',
    label: 'Manage Auth. Providers + Manage Users',
    perms: ['ManageAuthProviders', 'ManageUsers'],
    risk: 'HIGH',
    why: 'The user can reconfigure SSO/identity providers and administer accounts: enabling them to reroute authentication and impersonate or lock out other users.',
    fix: 'Restrict auth-provider management to a dedicated identity team, separate from user administration.',
  },
  {
    id: 'external-exfil-channel',
    label: 'Manage Connected Apps + Use Any API Client',
    perms: ['ManageConnectedApps', 'UseAnyApiClient'],
    risk: 'HIGH',
    why: 'The user can stand up OAuth connected apps and reach the org from any API client, bypassing API Access Control: a self-provisioned, persistent exfiltration channel.',
    fix: 'Keep connected-app administration away from users who can bypass API access control.',
  },
  {
    id: 'tamper-and-cover',
    label: 'Modify All Data + Manage Event Log Files',
    perms: ['ModifyAllData', 'ManageEventLogFiles'],
    risk: 'MEDIUM',
    why: 'The user can both alter data and access/aggregate the monitoring trail, weakening the ability to detect and reconstruct their actions.',
    fix: 'Keep monitoring/event-log access separate from broad data-modification rights.',
  },
];

export class SeparationOfDutiesCheck implements SecurityCheck {
  readonly id = 'separation-of-duties';
  readonly name = 'Separation of Duties';
  readonly category = 'Permissions';
  readonly description =
    'Flags users whose effective permissions combine into self-escalation, fraud, or undetectable-abuse pairings that violate separation of duties';

  readonly dependsOnCache = ['effectivePermissions'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ManageUsers/home`;
    const grants = ctx.cache.effectivePermissions;

    if (!grants) {
      findings.push({
        id: 'separation-of-duties-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Separation-of-duties analysis could not run',
        detail: 'Effective-permission data was not available (the privileged-access resolution did not complete).',
        remediation: 'Grant the audit user "View Setup and Configuration" and "View All Users", then re-run the audit.',
      });
      return { findings };
    }

    let anyViolation = false;
    for (const combo of COMBOS) {
      const holders = grants.filter((g) => {
        const s = new Set(g.perms);
        return combo.perms.every((p) => s.has(p));
      });
      if (holders.length === 0) continue;
      anyViolation = true;
      findings.push({
        id: `separation-of-duties-${combo.id}`,
        category: this.category,
        riskLevel: combo.risk,
        title: `${holders.length} user(s) hold a toxic permission combination: ${combo.label}`,
        detail: `${combo.why} Each permission may look acceptable in isolation, which is why combination review matters.`,
        remediation: combo.fix,
        affectedItems: holders.map((g) => ({
          label: g.username,
          url: setupUrl,
          note: `Profile: ${g.profileName}, holds ${combo.label}`,
        })),
      });
    }

    if (!anyViolation) {
      findings.push({
        id: 'separation-of-duties-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No toxic permission combinations detected',
        detail:
          grants.length === 0
            ? 'No active users hold catalogued high-risk permissions, so no separation-of-duties conflicts arise.'
            : 'No active user holds a flagged combination of permissions that would violate separation of duties.',
        remediation: 'Continue to separate user administration, code authorship, identity, and data-access duties across roles.',
      });
    }

    return { findings };
  }
}
