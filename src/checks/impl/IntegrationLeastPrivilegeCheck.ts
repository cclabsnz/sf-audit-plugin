import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import {
  resolveIntegrationAccounts,
  truncationDisclosure,
  type IntegrationAccount,
} from '../support/integrationAccounts.js';
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
 *
 * Second limit, disclosed on every write-evidence finding: this is the first check in the plugin
 * that queries record data rather than configuration. It aggregates ownership only — the queries
 * return owner ids and counts, never a field value — and it runs as the audit user with sharing
 * enforced, so it is conclusive only when that user holds View All Data. See
 * WRITE_VISIBILITY_CAVEAT and `recordVisibility`, and PERMISSIONS.md, which states the same thing
 * to the org owner.
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

/**
 * The write probe's own limit, disclosed wherever write evidence is reported.
 *
 * The record-count aggregate runs as the audit user with sharing enforced. An audit user with
 * object Read but no visibility of the records — restrictive org-wide defaults and no sharing rule,
 * which is exactly what a least-privilege audit account looks like — gets a successful query and
 * zero rows back, which is indistinguishable from "the integration never wrote here". Reporting
 * that as an unused grant would be a false accusation against a working integration, so the probe
 * runs only when the audit user is known to see all records.
 */
const WRITE_VISIBILITY_CAVEAT =
  'Write evidence is bounded by what the audit user can see: the record-count aggregate runs with sharing enforced, so records hidden from the audit user are indistinguishable from records that were never written. View All Data (or Modify All Data) on the audit user is required for this probe to be conclusive; without it every object is listed as unprobed rather than reported as unused.';

const DORMANT_DAYS = 90;

/** Two aggregates per object, so 30 objects. Anything dropped is named in the finding. */
const PROBE_QUERY_BUDGET = 60;
const OBJECT_CAP = PROBE_QUERY_BUDGET / 2;

interface ObjPermRow {
  ParentId: string;
  SobjectType: string;
  PermissionsCreate: boolean;
  PermissionsEdit: boolean;
  PermissionsDelete: boolean;
}

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
          // The enumeration lists what was actually matched against. connected-app run-as is not
          // implemented (the resolver reports it as degraded on every run), so naming it here would
          // tell the reader a signal was evaluated and found nothing when it was never gathered —
          // on the finding most likely to be read as "you have no integration accounts".
          'No active account matched an integration signal (Salesforce Integration licence, scheduled-job owner, never logged in, API-only logins, or a service-account username pattern), so there is no non-human identity holding surplus permissions.' +
          this.degradedNote(resolved.degraded) +
          truncationDisclosure(resolved.truncated),
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

    const truncationNote = truncationDisclosure(resolved.truncated);

    this.emit(findings, grants, ESCALATION_PERMS, permSetUrl, {
      id: 'integration-least-privilege-escalation-permissions',
      riskLevel: 'CRITICAL',
      title: 'escalation-grade permission(s)',
      detail:
        'These permissions let the holder change how the org runs, not merely read from it. Author Apex and Customize Application deploy code and metadata that execute in system context; Manage Users and Assign Permission Sets let the holder grant itself anything it does not already have. On an account with long-lived credentials and no interactive user to notice, each is a standing path to org control.',
      remediation:
        'Remove these from the integration account\'s profile and permission sets. An integration that genuinely deploys metadata should do so through a dedicated deployment identity with a change-managed credential, not through the account that runs its day-to-day traffic.',
      // Scoped to this class deliberately. Every permission above is exercisable over the API, so
      // the note is about who is exercising it, not whether it can be exercised — and it would be
      // meaningless attached to Password Never Expires or Data Export.
      apiOnlyNote:
        ' At least one of these accounts has no interactive login in the last 90 days, so no person is exercising these permissions through the UI. That is not evidence they are unused: each is reachable over the API — Author Apex through Metadata API deploys and anonymous Apex, Customize Application through metadata deploys, Manage Users and Assign Permission Sets through User and PermissionSetAssignment writes. Unless the integration itself deploys metadata or administers users, these grants are surplus to what its traffic needs.',
      suffix: truncationNote,
    });

    this.emit(findings, grants, DATA_PERMS, permSetUrl, {
      id: 'integration-least-privilege-data-permissions',
      riskLevel: 'HIGH',
      title: 'bulk-data or directory permission(s)',
      detail:
        'Data Export and View All Users reach past the object permissions an integration is scoped to: a full data export or the complete staff roster. An integration that moves specific records needs neither.',
      remediation:
        'Remove these and grant object- and field-level access scoped to the records the integration actually moves.',
      suffix: truncationNote,
    });

    this.emit(findings, grants, HYGIENE_PERMS, permSetUrl, {
      id: 'integration-least-privilege-hygiene',
      riskLevel: 'MEDIUM',
      title: 'standing-credential setting(s)',
      detail:
        'Password Never Expires on a service account means a credential that was correct in 2019 is still valid today, and that a rotation policy which appears to cover the org does not cover this account.',
      remediation:
        'Rotate the credential and move the integration to a certificate-based or OAuth JWT flow, where expiry is managed rather than disabled.',
      suffix: truncationNote,
    });

    // Dormancy is sourced from User.LastLoginDate, gathered by the candidate query above (which
    // has already succeeded by this point — resolveIntegrationAccounts returns early with
    // unavailable: true otherwise). It does not depend on the separate LoginHistory query that
    // feeds the api-only-login signal, so a degraded api-only-login signal does not affect this.
    const cutoff = Date.now() - DORMANT_DAYS * 86_400_000;
    const grantedIds = new Set(grants.map((g) => g.account.id));
    // Guard on lastLoginDate !== null: an account that has never logged in is not evidence of
    // dormancy — there is no "stopped being used" to observe. integration-users already reports
    // never-logged-in accounts as undocumented identities.
    const dormant = resolved.accounts.filter(
      (a) => grantedIds.has(a.id) && a.lastLoginDate !== null && new Date(a.lastLoginDate).getTime() < cutoff,
    );

    if (dormant.length > 0) {
      const dormantIds = new Set(dormant.map((a) => a.id));
      const withEscalation = grants.some((g) => g.permission in ESCALATION_PERMS && dormantIds.has(g.account.id));
      findings.push({
        id: 'integration-least-privilege-dormant',
        category: this.category,
        riskLevel: withEscalation ? 'HIGH' : 'MEDIUM',
        title: `${dormant.length} integration account(s) hold permissions but have not logged in for ${DORMANT_DAYS} days`,
        detail:
          `An account that has not authenticated in ${DORMANT_DAYS} days is not exercising any permission it holds, so every grant on it is surplus by definition. The credential remains valid, which is what makes a dormant privileged service account attractive to an attacker: nobody is watching an account nobody expects to be active, so use of it is unlikely to be noticed. ${READ_BLIND_SPOT}${truncationNote}`,
        remediation:
          'Confirm with the owning team whether the integration is retired. If it is, deactivate the account rather than merely stripping permissions. If it is seasonal, record that on the account so the next reviewer does not have to rediscover it.',
        affectedItems: dormant.slice(0, 30).map((a) => ({
          label: a.username,
          url: `${ctx.orgInfo.instanceUrl}/${a.id}`,
          note: `last login ${a.lastLoginDate!.split('T')[0]} | classified by: ${a.signals.join(', ')}`,
        })),
      });
    }

    let objPerms: ObjPermRow[] | null = null;
    // Tracks the ObjectPermissions query specifically failing (as opposed to succeeding with zero
    // rows), so that a failure here can also gate `-ok` below — write-evidence gathering that never
    // ran must not read as a clean bill any more than an unprobed object does.
    let objPermsUnavailable = false;
    const psIds = [...new Set(psa.map((p) => p.PermissionSetId))];
    try {
      if (psIds.length > 0) {
        objPerms = await ctx.soql.queryAll<ObjPermRow>(
          `SELECT ParentId, SobjectType, PermissionsCreate, PermissionsEdit, PermissionsDelete
           FROM ObjectPermissions
           WHERE ParentId IN (${psIds.map((i) => `'${i}'`).join(',')})
             AND (PermissionsCreate = true OR PermissionsEdit = true OR PermissionsDelete = true)`,
        );
      }
    } catch {
      objPerms = null; // Suppressed, not passed: ObjectPermissions failing must not read as a clean bill.
      objPermsUnavailable = true;
      findings.push({
        id: 'integration-least-privilege-object-permissions-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Object-level permissions could not be queried (insufficient access)',
        detail:
          'The ObjectPermissions query failed, so the Create, Edit and Delete grants held by these integration accounts could not be read. No statement can be made about write grants they hold and do not use. This does not affect the escalation-grade, bulk-data, hygiene or dormancy findings above, which are drawn from separate queries and still stand.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run.',
      });
    }

    if (objPerms && objPerms.length > 0) {
      // Widest over-grants first: rank by how many integration accounts hold write on the object.
      const accountsPerObject = new Map<string, Set<string>>();
      const psToAccounts = new Map<string, string[]>();
      for (const p of psa) {
        const list = psToAccounts.get(p.PermissionSetId) ?? [];
        list.push(p.AssigneeId);
        psToAccounts.set(p.PermissionSetId, list);
      }
      for (const op of objPerms) {
        const set = accountsPerObject.get(op.SobjectType) ?? new Set<string>();
        for (const a of psToAccounts.get(op.ParentId) ?? []) set.add(a);
        accountsPerObject.set(op.SobjectType, set);
      }

      const psMeta = new Map<string, { name: string; viaProfile: boolean }>();
      for (const p of psa) {
        if (p.PermissionSet) {
          psMeta.set(p.PermissionSetId, { name: p.PermissionSet.Name, viaProfile: p.PermissionSet.IsOwnedByProfile === true });
        }
      }
      const ordered = [...accountsPerObject.keys()].sort((a, b) => {
        const d = (accountsPerObject.get(b)?.size ?? 0) - (accountsPerObject.get(a)?.size ?? 0);
        return d !== 0 ? d : a.localeCompare(b);
      });

      // The probe is only meaningful if the audit user can see every record; see
      // WRITE_VISIBILITY_CAVEAT. When it cannot (or when that cannot be established), no object is
      // probed at all — the whole set goes to the unprobed list and the finding degrades to the
      // inconclusive shape rather than accusing a working integration of an unused grant.
      const visibility = await this.recordVisibility(ctx);
      const conclusive = visibility === 'sees-all-records';
      const probed = conclusive ? ordered.slice(0, OBJECT_CAP) : [];
      const skipped = conclusive ? ordered.slice(OBJECT_CAP) : [];
      const blind = conclusive ? [] : [...ordered];

      const unused: string[] = [];
      const probeFailures: string[] = [];
      for (const object of probed) {
        const wrote = await this.hasEverWritten(ctx, object, idList);
        if (wrote === null) probeFailures.push(object);
        else if (!wrote) unused.push(object);
      }

      // Probe failures first: they are the objects where something went wrong on this run, and the
      // list is capped for display. Ordering them behind budget-skipped objects pushed them out of
      // sight while still counting them in the title.
      const unprobed: { object: string; note: string }[] = [
        ...probeFailures.map((o) => ({ object: o, note: 'not probed — the record-count query failed; no conclusion drawn' })),
        ...blind.map((o) => ({
          object: o,
          note: visibility === 'no-view-all-data'
            ? 'not probed — audit user lacks View All Data, so absence of records proves nothing'
            : 'not probed — the audit user\'s record visibility could not be established',
        })),
        ...skipped.map((o) => ({ object: o, note: `not probed — beyond this run's ${OBJECT_CAP}-object probe budget` })),
      ];

      if (unused.length > 0 || unprobed.length > 0) {
        // Only needed to qualify the grant path on objects actually reported as unused.
        const sharedWith = unused.length > 0 ? await this.assigneesOutsideSet(ctx, psIds, idList) : new Map<string, number>();
        const capNote = skipped.length > 0
          ? ` ${skipped.length} object(s) were not probed for budget: the check probes at most ${OBJECT_CAP} objects per run, ordered by how many integration accounts hold write on them.`
          : '';
        const failureNote = probeFailures.length > 0
          ? ` ${probeFailures.length} object(s) were not probed because the record-count query failed against them.`
          : '';
        const blindNote = blind.length > 0
          ? visibility === 'no-view-all-data'
            ? ` ${blind.length} object(s) were not probed because the audit user does not hold View All Data or Modify All Data: without it the record-count query is bounded by sharing and cannot distinguish "never written" from "not visible to this audit user".`
            : ` ${blind.length} object(s) were not probed because the audit user's own record visibility could not be established on this run, so no absence of records could be read as evidence.`
          : '';
        // Controller ruling R5: an unused count of zero with only unprobed objects is not a
        // conclusion — it must not read as a graded finding about objects the check never queried.
        const inconclusiveOnly = unused.length === 0 && unprobed.length > 0;
        findings.push({
          id: 'integration-least-privilege-unused-write-objects',
          category: this.category,
          riskLevel: inconclusiveOnly ? 'INFO' : 'MEDIUM',
          inconclusive: inconclusiveOnly || undefined,
          title: inconclusiveOnly
            ? `${unprobed.length} object(s) with an integration write grant could not be checked for write evidence`
            : `${unused.length} object(s) carry an integration write grant with no record ever written`,
          detail:
            `For each object an integration account is granted Create, Edit or Delete on, the check looks for any record in the org attributed to that account by CreatedById or LastModifiedById. An object with no such record has a write grant the account has never exercised. Attribution is not perfect — a record the account wrote and someone else later edited no longer attributes to it — so treat this as strong evidence rather than proof. ${WRITE_VISIBILITY_CAVEAT}${failureNote}${blindNote}${capNote} ${READ_BLIND_SPOT}`,
          remediation:
            'Narrow Create, Edit and Delete on the listed objects at the grant named on each item. Check that grant before editing it: where the item says the profile or permission set is also assigned outside this integration set, removing the object permission there removes it for every one of those users — move the integration onto a dedicated permission set and narrow that instead. Where an object is genuinely written rarely, record that on the permission set so the next review does not re-raise it.',
          affectedItems: [
            ...unused.slice(0, 30).map((o) => ({
              label: o,
              url: permSetUrl,
              note: `write granted, never written | granted ${this.grantPathNote(o, objPerms!, psMeta, sharedWith)}`,
            })),
            ...unprobed.slice(0, 10).map((u) => ({ label: u.object, url: permSetUrl, note: u.note })),
          ],
        });
      }
    }

    if (findings.length === 0 && !objPermsUnavailable) {
      findings.push({
        id: 'integration-least-privilege-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${resolved.accounts.length} integration account(s); no surplus permission found`,
        detail:
          `No integration account holds an escalation-grade permission, a bulk-data permission or a standing-credential setting, none is dormant, and every probed object write grant has been exercised.${this.degradedNote(resolved.degraded)}${truncationDisclosure(resolved.truncated)} This result covers write grants and system permissions only. ${WRITE_VISIBILITY_CAVEAT} A Read grant an integration never exercises is not observable from SOQL, so this is not a statement that these accounts are at least privilege — run "sf audit apps" for read-side evidence from the RestApi event log.`,
        remediation:
          'Keep integration accounts on a dedicated permission set rather than a shared profile, and re-run after any integration is added or repurposed.',
      });
    }

    return { findings };
  }

  /** The degraded-signal qualification, agreeing in number with what was actually degraded. */
  private degradedNote(degraded: readonly string[]): string {
    if (degraded.length === 0) return '';
    const head = degraded.length === 1 ? 'One qualification' : `${degraded.length} qualifications`;
    const noun = degraded.length === 1 ? 'signal' : 'signals';
    const tail = degraded.length === 1 ? 'an account reachable only by it' : 'an account reachable only by one of them';
    return ` ${head}: the following classification ${noun} could not be gathered on this run — ${degraded.join(', ')} — so ${tail} was not examined.`;
  }

  /**
   * Whether the audit user itself can see every record in the org, which is what makes the write
   * probe conclusive (see WRITE_VISIBILITY_CAVEAT).
   *
   * `AuditContext` carries the org, not the running user, and there is no SOQL expression for
   * "the current user". The Connect API's `/chatter/users/me` is the one identity resource reachable
   * through the existing read-only REST client; orgs with Chatter disabled, or any unexpected
   * response, resolve as unknown. Every failure path returns a non-conclusive answer, so the worst
   * outcome is that write evidence is reported as ungathered — never that it is reported as clean.
   */
  private async recordVisibility(ctx: AuditContext): Promise<'sees-all-records' | 'no-view-all-data' | 'unknown'> {
    let me: { id?: unknown } | null = null;
    try {
      me = await ctx.rest.get<{ id?: unknown }>('/chatter/users/me');
    } catch {
      return 'unknown';
    }
    const id = typeof me?.id === 'string' ? me.id : '';
    // Validated as a User id before interpolation: an unexpected body must not reach a query.
    if (!/^005[0-9A-Za-z]{12}([0-9A-Za-z]{3})?$/.test(id)) return 'unknown';

    interface VisibilityRow {
      PermissionSet: { PermissionsViewAllData: boolean; PermissionsModifyAllData: boolean } | null;
    }
    try {
      const rows = await ctx.soql.queryAll<VisibilityRow>(
        `SELECT PermissionSet.PermissionsViewAllData, PermissionSet.PermissionsModifyAllData
         FROM PermissionSetAssignment WHERE AssigneeId = '${id}'`,
      );
      const seesAll = rows.some(
        (r) => r.PermissionSet?.PermissionsViewAllData === true || r.PermissionSet?.PermissionsModifyAllData === true,
      );
      return seesAll ? 'sees-all-records' : 'no-view-all-data';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Assignees of each granting permission set that are NOT in the resolved integration set.
   *
   * A grant reached through a profile, or through an org-wide permission set, is held by everyone
   * assigned to it. "Remove this object permission" is safe advice on a dedicated integration set
   * and destructive on a shared one, so the finding has to say which it is. Null when the count
   * could not be established — an unknown breadth is reported as unknown, not as exclusive.
   */
  private async assigneesOutsideSet(
    ctx: AuditContext,
    psIds: string[],
    idList: string,
  ): Promise<Map<string, number> | null> {
    if (psIds.length === 0) return new Map();
    try {
      const rows = await ctx.soql.queryAll<{ PermissionSetId: string; c: number }>(
        `SELECT PermissionSetId, COUNT(Id) c FROM PermissionSetAssignment
         WHERE PermissionSetId IN (${psIds.map((i) => `'${i}'`).join(',')})
           AND AssigneeId NOT IN (${idList})
         GROUP BY PermissionSetId`,
      );
      return new Map(rows.map((r) => [r.PermissionSetId, Number(r.c) || 0]));
    } catch {
      return null;
    }
  }

  /** Names the profile or permission set that grants write on `object`, and how widely it is held. */
  private grantPathNote(
    object: string,
    objPerms: ObjPermRow[],
    psMeta: Map<string, { name: string; viaProfile: boolean }>,
    sharedWith: Map<string, number> | null,
  ): string {
    const parents = [...new Set(objPerms.filter((p) => p.SobjectType === object).map((p) => p.ParentId))];
    const named = parents.map((parentId) => {
      const meta = psMeta.get(parentId);
      if (!meta) return `by an unidentified permission set (${parentId})`;
      const kind = meta.viaProfile ? 'profile' : 'permission set';
      if (sharedWith === null) return `via ${kind} ${meta.name} (how widely it is assigned could not be established — check before editing)`;
      const outside = sharedWith.get(parentId) ?? 0;
      return outside > 0
        ? `via ${kind} ${meta.name} (also assigned to ${outside} account(s) outside this integration set — removing it there removes it for all of them)`
        : `via ${kind} ${meta.name}`;
    });
    if (named.length === 0) return 'by a permission set this run could not identify';
    const shown = named.slice(0, 3).join('; ');
    return named.length > 3 ? `${shown}; and ${named.length - 3} more` : shown;
  }

  /**
   * True if the account wrote any record of this object, false if none, null if unprobeable.
   * Null must never be read as false — an object we could not query is not an unused grant.
   */
  private async hasEverWritten(ctx: AuditContext, object: string, idList: string): Promise<boolean | null> {
    for (const field of ['CreatedById', 'LastModifiedById']) {
      try {
        const rows = await ctx.soql.queryAll<Record<string, unknown>>(
          `SELECT ${field}, COUNT(Id) c FROM ${object} WHERE ${field} IN (${idList}) GROUP BY ${field}`,
        );
        if (rows.length > 0) return true;
      } catch {
        return null;
      }
    }
    return false;
  }

  /** Emits one finding for a permission class, or nothing when the class has no grants. */
  private emit(
    findings: Finding[],
    grants: Grant[],
    perms: Record<string, string>,
    url: string,
    shape: {
      id: string;
      riskLevel: Finding['riskLevel'];
      title: string;
      detail: string;
      remediation: string;
      /** Appended only when a matched account is api-only. Per-class, never shared across classes. */
      apiOnlyNote?: string;
      /** Appended unconditionally, e.g. a truncated account set. */
      suffix?: string;
    },
  ): void {
    const matched = grants.filter((g) => g.permission in perms);
    if (matched.length === 0) return;

    const apiOnly = matched.some((g) => g.account.signals.includes('api-only-login'));
    const apiNote = apiOnly ? (shape.apiOnlyNote ?? '') : '';

    findings.push({
      id: shape.id,
      category: this.category,
      riskLevel: shape.riskLevel,
      title: `${matched.length} ${shape.title} held by integration accounts`,
      detail: `${shape.detail}${apiNote} ${READ_BLIND_SPOT}${shape.suffix ?? ''}`,
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
