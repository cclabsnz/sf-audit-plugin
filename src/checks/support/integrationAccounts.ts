import type { AuditContext } from '@cclabsnz/sf-core';

export type IntegrationSignal =
  | 'integration-license'
  | 'connected-app-run-as'
  | 'scheduled-job-owner'
  | 'never-logged-in'
  | 'api-only-login'
  | 'username-pattern';

export interface IntegrationAccount {
  id: string;
  username: string;
  profileName: string;
  lastLoginDate: string | null;
  signals: IntegrationSignal[];
}

export interface ResolveResult {
  accounts: IntegrationAccount[];
  /** Signals that could not be gathered. Findings must disclose these. */
  degraded: IntegrationSignal[];
  /** True when the candidate query itself failed: callers go inconclusive. */
  unavailable: boolean;
}

/**
 * Username segments that strongly indicate a service/integration account. Moved here from
 * IntegrationUsersCheck so there is one definition rather than two that drift.
 */
export const SERVICE_LIKE_CLAUSES = [
  "Username LIKE '%service%'",
  "Username LIKE '%integration%'",
  "Username LIKE '%.api@%'",
  "Username LIKE '%\\_api\\_%'",
  "Username LIKE '%.svc@%'",
  "Username LIKE '%\\_svc\\_%'",
  "Username LIKE '%batch%'",
  "Username LIKE '%automation%'",
  "Username LIKE '%system@%'",
  "Username LIKE '%scheduler%'",
];

/** The same segments as a runtime matcher, for classifying rows the query returned. */
const SERVICE_LIKE_PATTERN =
  /service|integration|\.api@|_api_|\.svc@|_svc_|batch|automation|system@|scheduler/i;

/** Confirm against a live org before trusting — see the plan's live-org gate. */
const INTEGRATION_LICENSE = 'Salesforce Integration';

const NEVER_LOGGED_IN_MIN_AGE_DAYS = 30;

interface UserRow {
  Id: string;
  Username: string;
  Profile: { Name: string; UserLicense?: { Name: string } | null } | null;
  LastLoginDate: string | null;
  CreatedDate: string;
}

export async function resolveIntegrationAccounts(ctx: AuditContext): Promise<ResolveResult> {
  const degraded: IntegrationSignal[] = [];

  let rows: UserRow[];
  try {
    rows = await ctx.soql.queryAll<UserRow>(
      `SELECT Id, Username, Profile.Name, Profile.UserLicense.Name, LastLoginDate, CreatedDate
       FROM User
       WHERE IsActive = true
         AND ( Profile.UserLicense.Name = '${INTEGRATION_LICENSE}'
               OR (LastLoginDate = null AND CreatedDate < LAST_N_DAYS:${NEVER_LOGGED_IN_MIN_AGE_DAYS})
               OR ${SERVICE_LIKE_CLAUSES.join(' OR ')} )
         AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)
       ORDER BY LastLoginDate ASC NULLS FIRST
       LIMIT 200`,
    );
  } catch {
    return { accounts: [], degraded, unavailable: true };
  }

  const mapped = rows.map((r) => ({
    id: r.Id,
    username: r.Username,
    profileName: r.Profile?.Name ?? 'unknown',
    lastLoginDate: r.LastLoginDate,
    signals: intrinsicSignals(r),
  }));

  // A returned account with no signal is one the resolver cannot explain;
  // downstream findings name the signals as their justification.
  const accounts = mapped.filter((a) => a.signals.length > 0);

  return { accounts, degraded, unavailable: false };
}

function intrinsicSignals(r: UserRow): IntegrationSignal[] {
  const signals: IntegrationSignal[] = [];
  if (r.Profile?.UserLicense?.Name === INTEGRATION_LICENSE) signals.push('integration-license');
  if (r.LastLoginDate === null) signals.push('never-logged-in');
  if (SERVICE_LIKE_PATTERN.test(r.Username)) signals.push('username-pattern');
  return signals;
}
