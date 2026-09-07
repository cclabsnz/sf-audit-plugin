import { describeFields } from '@cclabsnz/sf-core';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

/**
 * Inventories standing OAuth authorisations from the `OauthToken` object.
 *
 * This exists because `connected-app-inactivity` cannot answer the question the 2025-2026
 * SaaS token-theft campaigns actually turn on. That check reads `LoginHistory` and calls an
 * app inactive when it has no OAuth login in 90 days. But a refresh token means the app never
 * needs to log in again: it presents the token and gets a new access token, and no
 * `LoginHistory` row of type `OAuth%` is created for the exchange. So an app can be reported
 * as dormant while still holding a working key to the org.
 *
 * That is the exact shape of the Salesloft Drift (Aug 2025), Gainsight (Nov 2025) and Klue
 * (Jun 2026) incidents: the vendor was breached, the tokens they already held were replayed
 * against customer orgs over the API, and the remediation in every case was to revoke access
 * and refresh tokens rather than to disable a login. An org cannot execute that remediation
 * without first knowing which apps hold live tokens and for how many users.
 *
 * Field discovery rather than a fixed SELECT list: `OauthToken` field availability varies by
 * API version and edition, and this repo does not query real orgs, so the field set is
 * intersected with `describe()` at runtime the same way `RTE_CATALOG` does it. A guessed
 * field name in a SELECT fails the whole query and reports an org as clean.
 */

interface OauthTokenRecord {
  AppName?: string | null;
  UserId?: string | null;
  LastUsedDate?: string | null;
  UseCount?: number | null;
  CreatedDate?: string | null;
}

/**
 * Priority order. `AppName` is the only one the check cannot work without.
 *
 * `OauthToken` also defines `AccessToken`, `RequestToken` and `DeleteToken`, all queryable
 * strings. None of them appear here and none may ever be added: findings are written to an HTML
 * or JSON report on disk, so selecting token material would turn an audit artefact into a
 * credential file. `NEVER_SELECT` is asserted in the unit tests.
 */
const PREFERRED_FIELDS = [
  'AppName',
  'UserId',
  'LastUsedDate',
  'UseCount',
  'CreatedDate',
] as const;

/** Queryable on OauthToken and permanently excluded: an audit report must not carry credentials. */
export const NEVER_SELECT = ['AccessToken', 'RequestToken', 'DeleteToken'] as const;

/** Ceiling on rows pulled. Large orgs hold a token per user per app, which multiplies fast. */
const MAX_TOKEN_ROWS = 5000;

/** A token unused for this long is a standing grant nobody is exercising. */
const STALE_DAYS = 90;

/**
 * Salesforce-owned clients that hold tokens in every org and are absent from
 * `ConnectedApplication` by design, so matching them against it always "fails". Confirmed
 * against a Developer Edition org on 2026-09-07, where `Salesforce CLI` and `orgfarm_app_1`
 * both held live tokens with an empty connected app inventory. Lower-cased for comparison.
 * A floor, not a complete list: an unrecognised first-party client is reported, which is the
 * safe direction to be wrong in.
 */
const FIRST_PARTY_APPS = new Set([
  'salesforce cli',
  'salesforce mobile dashboards',
  'salesforce for outlook',
  'salesforce dataloader',
  'dataloader partner',
  'dataloader bulk',
  'workbench',
  'sfdx cli',
  'salesforce inspector',
  'orgfarm_app_1',
]);

interface AppTokenSummary {
  app: string;
  tokens: number;
  users: Set<string>;
  lastUsed: string | null;
}

export class OauthTokenInventoryCheck implements SecurityCheck {
  readonly id = 'oauth-token-inventory';
  readonly name = 'Standing OAuth Token Inventory';
  readonly category = 'App Security';
  readonly description =
    'Inventories live OAuth tokens per app: a standing refresh token grants API access without any new login';

  readonly dependsOnCache = ['connectedAppNames'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ConnectedApplication/home`;

    let fields: string[] = [];
    try {
      const described = await describeFields(ctx.rest, 'OauthToken', PREFERRED_FIELDS);
      // Enforce the exclusion here rather than trusting the preferred list to stay clean.
      // describeFields returns what the org defines, and this check builds a SELECT that ends
      // up in a report file on disk, so the filter belongs at the point the query is built.
      fields = described.filter(
        (f) => !NEVER_SELECT.some((n) => n.toLowerCase() === f.toLowerCase())
      );
    } catch {
      findings.push(this.inconclusive('OauthToken could not be described'));
      return { findings };
    }

    if (!fields.includes('AppName')) {
      findings.push(
        this.inconclusive(
          'OauthToken does not expose AppName in this org, so tokens cannot be attributed to an app'
        )
      );
      return { findings };
    }

    let records: OauthTokenRecord[] = [];
    try {
      const result = await ctx.soql.query<OauthTokenRecord>(
        `SELECT ${fields.join(', ')} FROM OauthToken LIMIT ${MAX_TOKEN_ROWS}`
      );
      records = result.records ?? [];
    } catch {
      findings.push(
        this.inconclusive(
          'OauthToken was not readable. Standing OAuth grants cannot be inventoried without it'
        )
      );
      return { findings };
    }

    if (records.length === 0) {
      findings.push({
        id: 'oauth-token-inventory-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No standing OAuth tokens found',
        detail:
          'No rows were returned from OauthToken, so no app currently holds a standing OAuth authorisation in this org.',
        remediation: 'Re-check after authorising any new integration.',
      });
      return { findings };
    }

    // Aggregate client-side rather than with GROUP BY. Aggregate support varies across these
    // system objects, and a rejected GROUP BY would surface as "no tokens" rather than an error.
    const byApp = new Map<string, AppTokenSummary>();
    for (const r of records) {
      const app = (r.AppName ?? '').trim();
      if (!app) continue;
      const key = app.toLowerCase();
      let summary = byApp.get(key);
      if (!summary) {
        summary = { app, tokens: 0, users: new Set<string>(), lastUsed: null };
        byApp.set(key, summary);
      }
      summary.tokens += 1;
      if (r.UserId) summary.users.add(r.UserId);
      const used = r.LastUsedDate ?? null;
      if (used && (summary.lastUsed === null || used > summary.lastUsed)) {
        summary.lastUsed = used;
      }
    }

    const summaries = [...byApp.values()].sort((a, b) => b.tokens - a.tokens);
    const truncated = records.length >= MAX_TOKEN_ROWS;

    // The finding that matters: a live token whose app shows no recent interactive OAuth login.
    // connectedAppNames is what ConnectedAppsCheck saw in ConnectedApplication; an app holding
    // tokens that is absent from it is a grant with no current app definition behind it.
    const knownApps = new Set(
      (ctx.cache.connectedAppNames ?? []).map((n) => n.toLowerCase())
    );
    // With an empty inventory every token is trivially "unmatched", which on a real Developer
    // Edition org produced three HIGH findings for apps that were all benign. An org whose
    // ConnectedApplication read returned nothing has not been shown to have a problem, it has
    // failed to provide the evidence, so the comparison is skipped rather than assumed.
    const canCrossReference = knownApps.size > 0;
    const unmatched = canCrossReference
      ? summaries.filter(
          (s) =>
            !knownApps.has(s.app.toLowerCase()) && !FIRST_PARTY_APPS.has(s.app.toLowerCase())
        )
      : [];

    const cutoff = new Date(Date.now() - STALE_DAYS * 86_400_000).toISOString();
    const stale = summaries.filter((s) => s.lastUsed !== null && s.lastUsed < cutoff);
    const neverUsed = summaries.filter((s) => s.lastUsed === null);

    if (unmatched.length > 0) {
      findings.push({
        id: 'oauth-token-unmatched-app',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unmatched.length} app(s) hold live OAuth tokens but do not appear in the connected app inventory`,
        detail:
          `${unmatched.length} app name(s) on live OauthToken rows were not among the ${knownApps.size} connected apps read from ConnectedApplication. ` +
          'A standing token whose app definition is missing, renamed, or installed outside the connected app list is access nobody is reviewing. ' +
          'Because a refresh token is exchanged without producing an OAuth login row, this access does not appear in LoginHistory and will not be reported by the inactivity check.',
        remediation:
          'Identify each app. Where it is not a recognised integration with a named owner, revoke its tokens from the user detail page or via the OAuth Connected Apps Usage page, which invalidates the refresh token. Deactivating a user does not revoke a token that a third party holds.',
        affectedItems: unmatched.map((s) => ({
          label: s.app,
          url: setupUrl,
          note: `${s.tokens} token(s), ${s.users.size} user(s), last used ${s.lastUsed ?? 'never recorded'}`,
        })),
      });
    }

    if (!canCrossReference) {
      findings.push({
        id: 'oauth-token-no-app-inventory',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Standing tokens could not be cross-referenced against the connected app inventory',
        detail:
          'ConnectedApplication returned no rows, so tokens cannot be matched to a reviewable app definition. The inventory below is still accurate; only the comparison is missing.',
        remediation:
          'Grant the audit user read access to ConnectedApplication, then re-run so standing tokens can be matched against declared apps.',
      });
    }

    if (stale.length > 0 || neverUsed.length > 0) {
      const items = [...stale, ...neverUsed];
      findings.push({
        id: 'oauth-token-stale',
        category: this.category,
        riskLevel: items.length > 5 ? 'MEDIUM' : 'LOW',
        title: `${items.length} app(s) hold OAuth tokens unused for ${STALE_DAYS}+ days`,
        detail:
          `${stale.length} app(s) last used a token more than ${STALE_DAYS} days ago and ${neverUsed.length} have no recorded last-used date. ` +
          'An unused token is still a working credential. If the app or its vendor is compromised, the token is replayed against this org with no login and no user interaction.',
        remediation:
          'Revoke tokens for integrations that are no longer in use. Treat a vendor breach notification as a trigger to revoke every token for that publisher rather than waiting to confirm your own org was touched.',
        affectedItems: items.map((s) => ({
          label: s.app,
          url: setupUrl,
          note: `${s.tokens} token(s), ${s.users.size} user(s), last used ${s.lastUsed ?? 'never recorded'}`,
        })),
      });
    }

    findings.push({
      id: 'oauth-token-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${summaries.length} app(s) hold ${records.length}${truncated ? '+' : ''} standing OAuth token(s)`,
      detail:
        `Live OAuth authorisations by app, from OauthToken. Each row is an access or refresh token that can be exchanged for API access without a new login.` +
        (truncated
          ? ` Row cap of ${MAX_TOKEN_ROWS} was reached, so this is a floor rather than a complete count.`
          : '') +
        (fields.length < PREFERRED_FIELDS.length
          ? ` This org exposes ${fields.length} of ${PREFERRED_FIELDS.length} OauthToken fields, so some columns below are blank.`
          : ''),
      remediation:
        'Keep this list to integrations with a named owner and a business justification, and re-run it after any vendor breach disclosure.',
      affectedItems: summaries.map((s) => ({
        label: s.app,
        url: setupUrl,
        note: `${s.tokens} token(s), ${s.users.size} user(s), last used ${s.lastUsed ?? 'never recorded'}`,
      })),
    });

    return { findings };
  }

  private inconclusive(reason: string): Finding {
    return {
      id: 'oauth-token-inventory-inconclusive',
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: 'Standing OAuth tokens could not be inventoried',
      detail: `${reason}. Apps holding refresh tokens cannot be listed, and those grants do not appear in LoginHistory.`,
      remediation:
        'Grant the audit user read access to OauthToken, then re-run. Until then, review OAuth Connected Apps Usage in Setup by hand.',
    };
  }
}
