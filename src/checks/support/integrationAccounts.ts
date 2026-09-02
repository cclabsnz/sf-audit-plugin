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

  // connected-app-run-as is not implemented: confirming which object exposes a connected app's
  // run-as user requires a live-org describe, and this project forbids running against a real
  // org. Disclosing it unconditionally means every finding shows the gap instead of implying the
  // signal was gathered and found nothing.
  degraded.push('connected-app-run-as');

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

  const byId = new Map<string, IntegrationAccount>();
  for (const r of rows) {
    byId.set(r.Id, {
      id: r.Id,
      username: r.Username,
      profileName: r.Profile?.Name ?? 'unknown',
      lastLoginDate: r.LastLoginDate,
      signals: intrinsicSignals(r),
    });
  }

  const jobOwnerIds = await resolveJobOwnerIds(ctx, degraded);
  await mergePlatformSignal(ctx, byId, jobOwnerIds, 'scheduled-job-owner');

  await mergeApiOnlySignal(ctx, byId, degraded);

  // A returned account with no signal is one the resolver cannot explain; downstream findings
  // name the signals as their justification. This filter must run after every signal merge above
  // — an account reachable only through a platform signal (e.g. scheduled-job-owner) has no
  // intrinsic signals and would be dropped if this ran before the merge, defeating the point of
  // having the signal at all.
  const accounts = [...byId.values()].filter((a) => a.signals.length > 0);

  return { accounts, degraded, unavailable: false };
}

function intrinsicSignals(r: UserRow): IntegrationSignal[] {
  const signals: IntegrationSignal[] = [];
  if (r.Profile?.UserLicense?.Name === INTEGRATION_LICENSE) signals.push('integration-license');
  if (r.LastLoginDate === null) signals.push('never-logged-in');
  if (SERVICE_LIKE_PATTERN.test(r.Username)) signals.push('username-pattern');
  return signals;
}

/** Owners of scheduled Apex. An account that only runs jobs matches no username pattern. */
async function resolveJobOwnerIds(ctx: AuditContext, degraded: IntegrationSignal[]): Promise<string[]> {
  try {
    const jobs = await ctx.soql.queryAll<{ CreatedById: string }>(
      `SELECT CreatedById FROM AsyncApexJob
       WHERE JobType = 'ScheduledApex' AND CreatedDate = LAST_N_DAYS:90
       LIMIT 500`,
    );
    return [...new Set(jobs.map((j) => j.CreatedById).filter(Boolean))];
  } catch {
    degraded.push('scheduled-job-owner');
    return [];
  }
}

/**
 * Adds `signal` to accounts already resolved, and pulls in any id the candidate query missed.
 * An account reachable only by a platform signal is exactly the one the heuristics cannot see,
 * so dropping it here would defeat the point of having the signal.
 */
async function mergePlatformSignal(
  ctx: AuditContext,
  byId: Map<string, IntegrationAccount>,
  ids: string[],
  signal: IntegrationSignal,
): Promise<void> {
  if (ids.length === 0) return;

  const missing = ids.filter((id) => !byId.has(id));
  if (missing.length > 0) {
    try {
      const inList = missing.map((i) => `'${i}'`).join(',');
      const extra = await ctx.soql.queryAll<UserRow>(
        `SELECT Id, Username, Profile.Name, Profile.UserLicense.Name, LastLoginDate, CreatedDate
         FROM User WHERE IsActive = true AND Id IN (${inList})`,
      );
      for (const r of extra) {
        byId.set(r.Id, {
          id: r.Id,
          username: r.Username,
          profileName: r.Profile?.Name ?? 'unknown',
          lastLoginDate: r.LastLoginDate,
          signals: intrinsicSignals(r),
        });
      }
    } catch {
      // The signal's ids are known but the users are unreadable: the accounts we do have stand.
    }
  }

  for (const id of ids) {
    const acct = byId.get(id);
    if (acct && !acct.signals.includes(signal)) acct.signals.push(signal);
  }
}

interface LoginRow {
  UserId: string | null;
  Application: string | null;
  ApiType: string | null;
  logins: number;
}

const LOGIN_LOOKBACK_DAYS = 90;

/** A login that arrived over an API rather than an interactive session. */
function isApiLogin(row: LoginRow): boolean {
  return /soap|rest|bulk|api/i.test(row.ApiType ?? '') ||
         /api|soap|bulk|data ?loader/i.test(row.Application ?? '');
}

/**
 * Flags an account whose logins over the window are all API/SOAP/Bulk and never interactive.
 * Application and ApiType are groupable but not filterable on LoginHistory — a WHERE clause
 * naming either returns a parse error — so the query groups by them and this filters in memory.
 */
async function mergeApiOnlySignal(
  ctx: AuditContext,
  byId: Map<string, IntegrationAccount>,
  degraded: IntegrationSignal[],
): Promise<void> {
  let rows: LoginRow[];
  try {
    rows = await ctx.soql.queryAll<LoginRow>(
      `SELECT UserId, Application, ApiType, COUNT(Id) logins
       FROM LoginHistory
       WHERE LoginTime = LAST_N_DAYS:${LOGIN_LOOKBACK_DAYS}
       GROUP BY UserId, Application, ApiType`,
    );
  } catch {
    degraded.push('api-only-login');
    return;
  }

  const apiOnly = new Map<string, boolean>();
  for (const row of rows) {
    if (!row.UserId || !byId.has(row.UserId)) continue;
    const soFar = apiOnly.get(row.UserId);
    const thisRowIsApi = isApiLogin(row);
    apiOnly.set(row.UserId, soFar === false ? false : thisRowIsApi);
  }

  for (const [id, only] of apiOnly) {
    if (!only) continue;
    const acct = byId.get(id);
    if (acct && !acct.signals.includes('api-only-login')) acct.signals.push('api-only-login');
  }
}
