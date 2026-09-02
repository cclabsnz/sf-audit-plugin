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
  /**
   * True when the candidate query returned exactly its row limit, so the org may hold further
   * integration accounts this run never saw. Any finding that counts or lists accounts must
   * disclose it: SBS-ACS-007 asks for *all* non-human identities, and a truncated list that
   * reads as complete is the wrong answer to that control.
   */
  truncated: boolean;
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

/** Row cap on the candidate query. Hitting it sets `truncated`, which callers must disclose. */
const CANDIDATE_LIMIT = 200;

interface UserRow {
  Id: string;
  Username: string;
  Profile: { Name: string; UserLicense?: { Name: string } | null } | null;
  LastLoginDate: string | null;
  CreatedDate: string;
}

/**
 * The sentence findings use to disclose a truncated account set. Defined here, next to the limit
 * it describes, so the two checks cannot state different numbers.
 */
export function truncationDisclosure(truncated: boolean): string {
  if (!truncated) return '';
  return ` The candidate query returned its maximum of ${CANDIDATE_LIMIT} rows, so the account set is truncated: further integration or service accounts may exist in this org that this run never examined. Treat any count or list here as a floor rather than a complete inventory.`;
}

/**
 * One resolve per audit run, per context.
 *
 * Both `integration-users` and `integration-least-privilege` need the same account set, and the
 * resolver's slowest query is a 90-day `LoginHistory` aggregate — running it twice per audit buys
 * nothing. Memoising on the context object rather than `AuditCache` keeps this free of the
 * registry-ordering constraint that cache dependencies impose (see CheckEngine.validateCacheOrdering),
 * which the design deliberately avoided, and the WeakMap lets the whole result go when the context does.
 */
const inFlight = new WeakMap<AuditContext, Promise<ResolveResult>>();

export function resolveIntegrationAccounts(ctx: AuditContext): Promise<ResolveResult> {
  const cached = inFlight.get(ctx);
  if (cached) return cached;
  // A rejection must not be cached: the second caller would inherit a failure it never provoked
  // and could never retry. resolve() catches its own query failures (returning `unavailable`),
  // so this path is defensive rather than expected.
  const pending = resolve(ctx).catch((err: unknown) => {
    inFlight.delete(ctx);
    throw err;
  });
  inFlight.set(ctx, pending);
  return pending;
}

async function resolve(ctx: AuditContext): Promise<ResolveResult> {
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
       LIMIT ${CANDIDATE_LIMIT}`,
    );
  } catch {
    return { accounts: [], degraded, unavailable: true, truncated: false };
  }

  const truncated = rows.length >= CANDIDATE_LIMIT;

  const byId = new Map<string, IntegrationAccount>();
  for (const r of rows) byId.set(r.Id, toAccount(r));

  const jobOwnerIds = await resolveJobOwnerIds(ctx, degraded);
  await mergePlatformSignal(ctx, byId, jobOwnerIds, 'scheduled-job-owner');

  await mergeApiOnlySignal(ctx, byId, degraded);

  // A returned account with no signal is one the resolver cannot explain; downstream findings
  // name the signals as their justification. This filter must run after every signal merge above
  // — an account reachable only through a platform signal (e.g. scheduled-job-owner) has no
  // intrinsic signals and would be dropped if this ran before the merge, defeating the point of
  // having the signal at all.
  const accounts = [...byId.values()].filter((a) => a.signals.length > 0);

  return { accounts, degraded, unavailable: false, truncated };
}

/**
 * One row → account mapping, used by both the candidate loop and the platform-signal enrichment
 * loop. Two copies of this is how the two paths would drift: an account pulled in by a platform
 * signal must be described exactly as one the candidate query returned.
 */
function toAccount(r: UserRow): IntegrationAccount {
  return {
    id: r.Id,
    username: r.Username,
    profileName: r.Profile?.Name ?? 'unknown',
    lastLoginDate: r.LastLoginDate,
    signals: intrinsicSignals(r),
  };
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
      for (const r of extra) byId.set(r.Id, toAccount(r));
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

/**
 * A login that arrived over an API rather than an interactive session.
 *
 * `Application` is a free-text client name, so the alternatives are word-bounded: an unanchored
 * `api` matches the "api" inside a connected app called "Rapid7 Insight", which would stamp
 * `api-only-login` on an interactive login and, through it, an aggravating note on a CRITICAL
 * finding. `ApiType` is a controlled vocabulary ("SOAP Partner", "REST", "Bulk"), so substring
 * matching there is safe and is what actually carries most API logins.
 *
 * The same LoginHistory Application/ApiType classification is used by `SoapLoginApiAuthCheck`'s
 * `isSoapLogin`, which stays deliberately broad — it grades readiness for a release update, where
 * over-matching costs a needless review, whereas over-matching here mislabels an account.
 */
function isApiLogin(row: LoginRow): boolean {
  return /soap|rest|bulk|api/i.test(row.ApiType ?? '') ||
         /\b(api|soap|bulk|data ?loader)\b/i.test(row.Application ?? '');
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
