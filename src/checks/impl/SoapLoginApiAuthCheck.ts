import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

/**
 * Winter '27 release update: "Assign Use Any API Auth Permission for SOAP login()".
 * Users without the permission can no longer authenticate with SOAP API login().
 *
 * This check is inverted relative to the rest of the Permissions category. Every other
 * check here flags a permission being PRESENT; this one flags it being ABSENT on an
 * account that needs it. The failure mode is a broken integration at authentication
 * time, server to server, with nothing in the UI to signal it.
 *
 * Not to be confused with `api-client-permission` (SBS-ACS-006), which covers
 * "Use Any API Client". They are separate permissions: PermissionsUseAnyApiAuth exists
 * on PermissionSet and Profile, and there is no PermissionsUseAnyApiClient field at all.
 * Published coverage of the Winter '27 change routinely conflates the two, and granting
 * the wrong one leaves an org exposed to the breakage while feeling remediated.
 */

/** Aggregate row from LoginHistory. Application and ApiType are groupable, never filterable. */
interface LoginAggregateRecord {
  UserId: string | null;
  Application: string | null;
  ApiType: string | null;
  logins: number;
}

interface UserRecord {
  Id: string;
  Username: string;
  Profile?: { Name: string };
}

interface PsaRecord {
  Assignee: { Id: string; Username: string; Profile?: { Name: string } };
  PermissionSet: { Name: string; IsOwnedByProfile?: boolean };
}

/**
 * Ninety days rather than thirty. SOAP callers are disproportionately the least routine
 * things in an org: a quarterly reconciliation job, a backup tool, a device switched on
 * for stocktake. A short window is exactly how those get missed.
 */
const LOOKBACK_DAYS = 90;

/**
 * Matched against ApiType first, which carries values such as "SOAP Partner" and
 * "SOAP Enterprise", then Application as a fallback. The match is deliberately broad:
 * the exact strings are not contractual and vary by how the client identifies itself.
 */
function isSoapLogin(row: LoginAggregateRecord): boolean {
  return /soap/i.test(row.ApiType ?? '') || /soap/i.test(row.Application ?? '');
}

export class SoapLoginApiAuthCheck implements SecurityCheck {
  readonly id = 'soap-login-api-auth';
  readonly name = 'SOAP login() Use Any API Auth Readiness';
  readonly category = 'Permissions';
  readonly description =
    'Flags accounts that authenticate via SOAP API login() but lack the "Use Any API Auth" permission that Winter \'27 requires, and holders that no longer need it';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const permSetUrl = `${baseUrl}/lightning/setup/PermSets/home`;

    // Q1: who is authenticating over SOAP.
    // Application, Status and ApiType are groupable but NOT filterable on LoginHistory,
    // so a WHERE clause naming them returns a parse error. Group, then filter in memory.
    let soapRows: LoginAggregateRecord[] = [];
    try {
      const result = await ctx.soql.query<LoginAggregateRecord>(
        `SELECT UserId, Application, ApiType, COUNT(Id) logins
         FROM LoginHistory
         WHERE LoginTime = LAST_N_DAYS:${LOOKBACK_DAYS}
         GROUP BY UserId, Application, ApiType`
      );
      soapRows = result.records.filter(isSoapLogin).filter((r) => r.UserId);
    } catch {
      findings.push({
        id: 'soap-login-api-auth-inconclusive-history',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'SOAP login() readiness could not be determined: LoginHistory was not readable',
        detail:
          'Winter \'27 requires the "Use Any API Auth" permission to authenticate with SOAP API login(). Determining exposure needs LoginHistory, which this audit user could not query. LoginHistory also retains only six months, so an integration that runs less often than that may not appear even when readable.',
        remediation:
          'Re-run with a user that can read LoginHistory, or review Setup → Identity → Login History manually, filtering for SOAP API types.',
      });
      return { findings };
    }

    // Q2: who already holds the permission. Querying PermissionSetAssignment covers both
    // grant paths, because a profile's own permissions live on a PermissionSet with
    // IsOwnedByProfile = true. Orgs on a release without the field will throw here.
    let holders: PsaRecord[] = [];
    try {
      const result = await ctx.soql.query<PsaRecord>(
        `SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name,
                PermissionSet.Name, PermissionSet.IsOwnedByProfile
         FROM PermissionSetAssignment
         WHERE PermissionSet.PermissionsUseAnyApiAuth = true
           AND Assignee.IsActive = true`
      );
      holders = result.records;
    } catch {
      findings.push({
        id: 'soap-login-api-auth-inconclusive-field',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: '"Use Any API Auth" permission is not queryable in this org yet',
        detail:
          'The PermissionsUseAnyApiAuth field was not available. That is expected on orgs not yet upgraded to a release that carries it, and it means readiness for the Winter \'27 SOAP login() change cannot be assessed here. Note this permission is not the same as "Use Any API Client", which is covered separately by the api-client-permission check.',
        remediation:
          `Re-run this audit after the org takes Winter '27, or check Setup → Permission Sets for "Use Any API Auth" directly: ${permSetUrl}`,
      });
      return { findings };
    }

    const holderIds = new Set(holders.map((h) => h.Assignee.Id));

    if (soapRows.length === 0) {
      findings.push({
        id: 'soap-login-api-auth-ok-no-soap',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `No SOAP API login() authentication in the last ${LOOKBACK_DAYS} days`,
        detail:
          `Winter '27 requires the "Use Any API Auth" permission to authenticate with SOAP API login(). No login in the last ${LOOKBACK_DAYS} days used a SOAP API type, so no account is exposed to that change on the evidence available. LoginHistory retains six months, so an integration that runs less frequently than this window would not appear.`,
        remediation:
          'No action needed. If you operate an integration that runs less often than quarterly, confirm its authentication method directly rather than relying on this window.',
      });
      return { findings };
    }

    // Resolve usernames for the SOAP callers. LoginHistory gives UserId only, and an
    // aggregate query cannot traverse to User reliably.
    const soapUserIds = [...new Set(soapRows.map((r) => r.UserId as string))];
    const idList = soapUserIds.map((id) => `'${id}'`).join(',');
    const userResult = await ctx.soql.query<UserRecord>(
      `SELECT Id, Username, Profile.Name FROM User WHERE Id IN (${idList}) AND IsActive = true`
    );
    const users = new Map(userResult.records.map((u) => [u.Id, u]));

    // Login counts per user, summed across the Application/ApiType rows they appear in.
    const loginCounts = new Map<string, number>();
    for (const row of soapRows) {
      const id = row.UserId as string;
      loginCounts.set(id, (loginCounts.get(id) ?? 0) + (row.logins ?? 0));
    }

    const atRisk = soapUserIds.filter((id) => users.has(id) && !holderIds.has(id));

    if (atRisk.length === 0) {
      findings.push({
        id: 'soap-login-api-auth-ok-covered',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${soapUserIds.length} SOAP login() account(s) already hold "Use Any API Auth"`,
        detail:
          `Every active account that authenticated over SOAP in the last ${LOOKBACK_DAYS} days holds the permission Winter '27 requires, so the enforcement should not break these integrations.`,
        remediation:
          'Keep the grant scoped to these accounts. If a new integration is onboarded, assign the same permission set rather than widening a profile.',
      });
    } else {
      findings.push({
        id: 'soap-login-api-auth-missing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${atRisk.length} account(s) authenticate via SOAP login() without "Use Any API Auth": these break in Winter '27`,
        detail:
          `Winter '27 enforces the "Assign Use Any API Auth Permission for SOAP login()" release update. Salesforce states that users without the permission "can no longer authenticate with SOAP API login() and will encounter an error". These accounts authenticated over SOAP in the last ${LOOKBACK_DAYS} days and do not hold the permission through any profile or permission set. The failure occurs at authentication, server to server, so there is no error in the Salesforce UI and no partial transaction to unpick. Whoever monitors the downstream system finds out first. Note this is a different permission from "Use Any API Client"; granting that one does not satisfy this requirement.`,
        remediation:
          `Create a permission set enabling "Use Any API Auth" and assign it to exactly these accounts, rather than editing a profile, so the grant stays visible in one query and revocable without collateral. Name it for the reason it exists. Before granting, confirm each account still needs SOAP: an integration that can move to the REST API or to a modern OAuth flow is better migrated than permitted. ${permSetUrl}`,
        affectedItems: atRisk.map((id) => {
          const u = users.get(id) as UserRecord;
          return {
            label: u.Username,
            url: `${baseUrl}/${id}`,
            note: `${loginCounts.get(id) ?? 0} SOAP login(s) in ${LOOKBACK_DAYS}d, profile: ${u.Profile?.Name ?? 'unknown'}`,
          };
        }),
      });
    }

    // The security half. A permission granted to accounts that do not use SOAP is standing
    // privilege with no purpose, and orgs remediating the breakage in a hurry tend to create
    // exactly that by granting at profile level.
    const unnecessary = holders.filter((h) => !soapUserIds.includes(h.Assignee.Id));
    if (unnecessary.length > 0) {
      const viaProfile = unnecessary.filter((h) => h.PermissionSet.IsOwnedByProfile);
      findings.push({
        id: 'soap-login-api-auth-unnecessary',
        category: this.category,
        riskLevel: viaProfile.length > 0 ? 'MEDIUM' : 'LOW',
        title: `${unnecessary.length} account(s) hold "Use Any API Auth" without using SOAP login()`,
        detail:
          `These active accounts hold the permission but did not authenticate over SOAP in the last ${LOOKBACK_DAYS} days, so the grant is not currently doing anything for them. ${
            viaProfile.length > 0
              ? `${viaProfile.length} of them receive it through a profile, which means it applies to everyone sharing that profile now and in future rather than to a named account.`
              : 'All of them receive it through an assigned permission set, which is the right mechanism even where the grant turns out to be unnecessary.'
          } Granting broadly is a common response to the Winter '27 change and it converts a breakage problem into a standing-privilege one.`,
        remediation:
          'Remove the permission from accounts that do not authenticate over SOAP. Where it is granted by a profile, move it to a permission set assigned to the specific integration accounts that need it. Check against a longer window than this audit uses before removing, since a quarterly job may sit outside it.',
        affectedItems: unnecessary.map((h) => ({
          label: h.Assignee.Username,
          url: `${baseUrl}/${h.Assignee.Id}`,
          note: `via: ${h.PermissionSet.IsOwnedByProfile ? `Profile (${h.Assignee.Profile?.Name ?? 'unknown'})` : h.PermissionSet.Name}`,
        })),
      });
    }

    return { findings };
  }
}
