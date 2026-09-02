import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { resolveIntegrationAccounts, type IntegrationAccount } from '../support/integrationAccounts.js';
import { PERM_BY_KEY } from '../permCatalog.js';

/**
 * What an integration account holds that it does not need.
 *
 * The org already knows what these accounts are granted; nothing until now asked whether any of it
 * is exercised. An integration account is the worst place for standing privilege: no interactive
 * user to notice, long-lived credentials by design, and frequently outside MFA and IP restrictions
 * because those break server-to-server callers.
 *
 * Findings are split by attacker-capability class rather than lumped under one id, because
 * CAPABILITY_REGISTRY is keyed on finding id — Author Apex (code-exec, priv-esc) and Password Never
 * Expires cannot share an id without the chain model losing the distinction.
 *
 * Field source discipline (controller ruling R12): every field name below is sourced from
 * `permCatalog.ts` — this repo's canonical, live-org-verified vocabulary of PermissionSet.Permissions*
 * fields — except `PermissionsDataExport`, which is not in the catalog but is verified by its live
 * use in `DataExportAccessCheck.ts`. One invalid field name fails the whole PermissionSetAssignment
 * query with INVALID_FIELD, which would leave this check permanently inconclusive, so nothing here
 * is invented.
 *
 * Scope discipline (controller ruling R13): the three classes below are exactly Escalation (Author
 * Apex, Customize Application, Manage Users, Assign Permission Sets), Data (Data Export, View All
 * Users), and Hygiene (Password Never Expires). The catalog holds further escalation-grade
 * permissions (Modify Metadata, Manage Internal Users, Manage Auth. Providers, Manage Connected
 * Apps) that are deliberately NOT included here — widening this check mid-plan is scope creep,
 * logged as a follow-up rather than done inline.
 *
 * Modify All Data and View All Data are deliberately absent: `integration-users` already grades
 * them against SBS-ACS-008, and a second id would double-count in both the score and the chains.
 *
 * Limit, disclosed on every finding: this check runs inside `audit security`, which has SOQL but no
 * EventLogFile bodies. A Read grant an integration never exercises is not observable here.
 */

/** Permission API name → label, sourced from permCatalog.ts's DangerousPerm entries. */
const ESCALATION_PERMS: Record<string, string> = {
  [PERM_BY_KEY.AuthorApex!.field]: PERM_BY_KEY.AuthorApex!.label,
  [PERM_BY_KEY.CustomizeApplication!.field]: PERM_BY_KEY.CustomizeApplication!.label,
  [PERM_BY_KEY.ManageUsers!.field]: PERM_BY_KEY.ManageUsers!.label,
  [PERM_BY_KEY.AssignPermissionSets!.field]: PERM_BY_KEY.AssignPermissionSets!.label,
};

const DATA_PERMS: Record<string, string> = {
  // Not in permCatalog.ts; verified live by DataExportAccessCheck.ts's own PermissionSetAssignment
  // query, which already selects this exact field name.
  PermissionsDataExport: 'Data Export',
  [PERM_BY_KEY.ViewAllUsers!.field]: PERM_BY_KEY.ViewAllUsers!.label,
};

const HYGIENE_PERMS: Record<string, string> = {
  [PERM_BY_KEY.PasswordNeverExpires!.field]: PERM_BY_KEY.PasswordNeverExpires!.label,
};

const ALL_PERMS = { ...ESCALATION_PERMS, ...DATA_PERMS, ...HYGIENE_PERMS };

interface PsaRow {
  AssigneeId: string;
  PermissionSetId: string;
  PermissionSet: ({ Name: string; IsOwnedByProfile: boolean } & Record<string, boolean | string>) | null;
}

interface Grant {
  account: IntegrationAccount;
  permission: string;
  label: string;
  viaProfile: boolean;
  grantName: string;
}

const READ_BLIND_SPOT =
  'This check sees permission grants, not read traffic: a Read grant an integration never exercises is not observable from SOQL. Run "sf audit apps" for read-side evidence.';

export class IntegrationLeastPrivilegeCheck implements SecurityCheck {
  readonly id = 'integration-least-privilege';
  readonly name = 'Integration Account Least Privilege';
  readonly category = 'Permissions';
  readonly description =
    'Reports permissions held by integration and service accounts that the account is not using — escalation-grade permissions, bulk-data permissions, and standing-credential settings';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const permSetUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/PermSets/home`;

    const resolved = await resolveIntegrationAccounts(ctx);
    if (resolved.unavailable) {
      findings.push(this.inconclusive('integration-least-privilege-inaccessible', 'Integration accounts could not be enumerated'));
      return { findings };
    }
    if (resolved.accounts.length === 0) {
      findings.push({
        id: 'integration-least-privilege-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No integration or service accounts found',
        detail:
          'No active account matched an integration signal (Salesforce Integration licence, connected-app run-as user, scheduled-job owner, never logged in, API-only logins, or a service-account username pattern), so there is no non-human identity holding surplus permissions.',
        remediation:
          'As integration accounts are created, grant them a dedicated permission set scoped to the objects and operations they actually use, rather than a broad profile.',
      });
      return { findings };
    }

    const byId = new Map(resolved.accounts.map((a) => [a.id, a]));
    const idList = resolved.accounts.map((a) => `'${a.id}'`).join(',');
    const permFields = Object.keys(ALL_PERMS).map((p) => `PermissionSet.${p}`).join(', ');

    let psa: PsaRow[];
    try {
      psa = await ctx.soql.queryAll<PsaRow>(
        `SELECT AssigneeId, PermissionSetId, PermissionSet.Name, PermissionSet.IsOwnedByProfile, ${permFields}
         FROM PermissionSetAssignment WHERE AssigneeId IN (${idList})`,
      );
    } catch {
      findings.push(
        this.inconclusive('integration-least-privilege-permissions-inaccessible', 'Integration account permissions could not be queried'),
      );
      return { findings };
    }

    const grants: Grant[] = [];
    for (const row of psa) {
      const ps = row.PermissionSet;
      const account = byId.get(row.AssigneeId);
      if (!ps || !account) continue;
      for (const [permission, label] of Object.entries(ALL_PERMS)) {
        if (ps[permission] === true) {
          grants.push({ account, permission, label, viaProfile: ps.IsOwnedByProfile === true, grantName: ps.Name });
        }
      }
    }

    this.emit(findings, grants, ESCALATION_PERMS, permSetUrl, {
      id: 'integration-least-privilege-escalation-permissions',
      riskLevel: 'CRITICAL',
      title: 'escalation-grade permission(s)',
      detail:
        'These permissions let the holder change how the org runs, not merely read from it. Author Apex and Customize Application deploy code and metadata that execute in system context; Manage Users and Assign Permission Sets let the holder grant itself anything it does not already have. On an account with long-lived credentials and no interactive user to notice, each is a standing path to org control.',
      remediation:
        'Remove these from the integration account\'s profile and permission sets. An integration that genuinely deploys metadata should do so through a dedicated deployment identity with a change-managed credential, not through the account that runs its day-to-day traffic.',
    });

    this.emit(findings, grants, DATA_PERMS, permSetUrl, {
      id: 'integration-least-privilege-data-permissions',
      riskLevel: 'HIGH',
      title: 'bulk-data or directory permission(s)',
      detail:
        'Data Export and View All Users reach past the object permissions an integration is scoped to: a full data export or the complete staff roster. An integration that moves specific records needs neither.',
      remediation:
        'Remove these and grant object- and field-level access scoped to the records the integration actually moves.',
    });

    this.emit(findings, grants, HYGIENE_PERMS, permSetUrl, {
      id: 'integration-least-privilege-hygiene',
      riskLevel: 'MEDIUM',
      title: 'standing-credential setting(s)',
      detail:
        'Password Never Expires on a service account means a credential that was correct in 2019 is still valid today, and that a rotation policy which appears to cover the org does not cover this account.',
      remediation:
        'Rotate the credential and move the integration to a certificate-based or OAuth JWT flow, where expiry is managed rather than disabled.',
    });

    return { findings };
  }

  /** Emits one finding for a permission class, or nothing when the class has no grants. */
  private emit(
    findings: Finding[],
    grants: Grant[],
    perms: Record<string, string>,
    url: string,
    shape: { id: string; riskLevel: Finding['riskLevel']; title: string; detail: string; remediation: string },
  ): void {
    const matched = grants.filter((g) => g.permission in perms);
    if (matched.length === 0) return;

    findings.push({
      id: shape.id,
      category: this.category,
      riskLevel: shape.riskLevel,
      title: `${matched.length} ${shape.title} held by integration accounts`,
      detail: `${shape.detail} ${READ_BLIND_SPOT}`,
      remediation: shape.remediation,
      affectedItems: matched.slice(0, 30).map((g) => ({
        label: `${g.account.username} — ${g.label}`,
        url,
        note: `${g.label} ${g.viaProfile ? `via profile ${g.grantName}` : `via permission set ${g.grantName}`} | classified by: ${g.account.signals.join(', ')}`,
      })),
    });
  }

  private inconclusive(id: string, what: string): Finding {
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather the data needed to evaluate integration account privilege.',
      remediation: 'Grant the audit user View Setup and Configuration and re-run.',
    };
  }
}
