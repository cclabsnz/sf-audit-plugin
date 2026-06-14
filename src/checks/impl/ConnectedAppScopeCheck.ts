import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ConnectedAppScopeRecord {
  Id: string;
  Name: string;
  Metadata: {
    oauthConfig?: {
      scopes?: string[];
      isRefreshTokenRotationEnabled?: boolean;
      refreshTokenValidityPeriod?: number;
    };
    oauthPolicy?: {
      refreshTokenPolicy?: string;
    };
  } | null;
}

// Scopes that grant effectively unlimited access as the authorising user.
const OVERLY_BROAD_SCOPES = new Set(['Full', 'full']);

// Refresh token policy values that indicate no expiry.
// refreshTokenValidityPeriod = -1 means "use org default" (often hours or longer).
// oauthPolicy.refreshTokenPolicy = 'infinite' means no expiry at all.
function isInfiniteRefreshToken(app: ConnectedAppScopeRecord): boolean {
  const validityPeriod = app.Metadata?.oauthConfig?.refreshTokenValidityPeriod;
  const policy = app.Metadata?.oauthPolicy?.refreshTokenPolicy;
  return validityPeriod === -1 || policy === 'infinite';
}

export class ConnectedAppScopeCheck implements SecurityCheck {
  readonly id = 'connected-app-scope';
  readonly name = 'Connected App OAuth Scopes & Token Policy';
  readonly category = 'App Security';
  readonly description = 'Flags connected apps granting Full OAuth scope or using infinite refresh token policies — both expand the blast radius of a compromised token';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ConnectedApplication/home`;

    let apps: ConnectedAppScopeRecord[] = [];
    try {
      apps = await ctx.tooling.query<ConnectedAppScopeRecord>(
        'SELECT Id, Name, Metadata FROM ConnectedApplication'
      );
    } catch {
      findings.push({
        id: 'connected-app-scope-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Connected app OAuth scope check could not be completed',
        detail: 'ConnectedApplication Metadata was not accessible via Tooling API. This may indicate a permissions issue on the audit user.',
        remediation: 'Grant the audit user the "Customize Application" permission to enable Tooling API access to connected app metadata.',
      });
      return { findings };
    }

    if (apps.length === 0) {
      findings.push({
        id: 'connected-app-scope-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No connected apps found',
        detail: 'No connected apps exist in this org.',
        remediation: 'Continue monitoring as new connected apps are added.',
      });
      return { findings };
    }

    const fullScopeApps: ConnectedAppScopeRecord[] = [];
    const infiniteTokenApps: ConnectedAppScopeRecord[] = [];

    for (const app of apps) {
      const scopes = app.Metadata?.oauthConfig?.scopes ?? [];
      if (scopes.some((s) => OVERLY_BROAD_SCOPES.has(s))) {
        fullScopeApps.push(app);
      }
      // Only flag infinite refresh tokens if the app has at least one scope
      // (apps with no scopes are non-OAuth apps and don't issue tokens)
      if (scopes.length > 0 && isInfiniteRefreshToken(app)) {
        infiniteTokenApps.push(app);
      }
    }

    if (fullScopeApps.length > 0) {
      findings.push({
        id: 'connected-app-full-scope',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${fullScopeApps.length} connected app(s) grant the "Full" OAuth scope`,
        detail:
          'The Full OAuth scope gives a connected app the same access rights as the authorising user — including Modify All Data if the user is an admin. A stolen access or refresh token from a Full-scope app can be used to read, write, and delete any record the user could access. Full scope is almost never necessary; specific scopes (Api, Web, CustomPermissions) should be used instead.',
        remediation:
          'Edit each connected app in Setup → Connected Apps → OAuth Policies and replace "Full" scope with the minimum scopes the integration actually requires. Common replacements: "Api" for REST API access, "Web" for web-based flows, "OpenID" + "Profile" for identity only. Rotating client secrets after scope changes is also recommended.',
        affectedItems: fullScopeApps.map((app) => ({
          label: app.Name,
          url: setupUrl,
          note: `Scopes: ${(app.Metadata?.oauthConfig?.scopes ?? []).join(', ')}`,
        })),
      });
    }

    if (infiniteTokenApps.length > 0) {
      // Exclude apps already flagged for Full scope from the infinite-token list to avoid double-counting
      const infiniteOnlyApps = infiniteTokenApps.filter(
        (app) => !fullScopeApps.some((fa) => fa.Id === app.Id)
      );

      if (infiniteOnlyApps.length > 0) {
        findings.push({
          id: 'connected-app-infinite-refresh-token',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${infiniteOnlyApps.length} connected app(s) issue refresh tokens with no expiry`,
          detail:
            'Connected apps with an infinite or org-default refresh token policy (refreshTokenValidityPeriod = -1 or policy = "infinite") issue tokens that never expire unless manually revoked. A stolen refresh token provides indefinite access to the org as the authorising user. SBS-DEP-006 requires access token lifetimes of 15 minutes or less; refresh token lifetimes should also be bounded.',
          remediation:
            'Set an explicit refresh token validity period in Setup → Connected Apps → OAuth Policies. For machine-to-machine integrations, consider using the Client Credentials flow (which does not issue refresh tokens) instead of the Authorization Code flow. For user-facing apps, a 90-day refresh token limit is a reasonable starting point.',
          affectedItems: infiniteOnlyApps.map((app) => ({
            label: app.Name,
            url: setupUrl,
            note: `RefreshTokenPolicy: ${app.Metadata?.oauthPolicy?.refreshTokenPolicy ?? 'unset'}, ValidityPeriod: ${app.Metadata?.oauthConfig?.refreshTokenValidityPeriod ?? 'unset'}`,
          })),
        });
      }

      // Also flag Full-scope apps that ALSO have infinite refresh tokens as a compound risk note
      const fullAndInfinite = fullScopeApps.filter((app) =>
        infiniteTokenApps.some((ia) => ia.Id === app.Id)
      );
      if (fullAndInfinite.length > 0) {
        findings.push({
          id: 'connected-app-full-scope-infinite-token',
          category: this.category,
          riskLevel: 'CRITICAL',
          title: `${fullAndInfinite.length} connected app(s) combine Full scope with an infinite refresh token — stolen token = permanent full access`,
          detail:
            'These apps issue never-expiring tokens that grant complete access to the org as the authorising user. A single leaked token is equivalent to a permanent credential with admin-level reach if the user is an admin. This is the highest-risk connected app configuration.',
          remediation:
            'Immediately restrict scopes to the minimum required and set an explicit refresh token expiry. If Full scope cannot be removed, at minimum set a refresh token validity period of 90 days or less and enable refresh token rotation.',
          affectedItems: fullAndInfinite.map((app) => ({
            label: app.Name,
            url: setupUrl,
            note: `Full scope + infinite refresh token — highest risk combination`,
          })),
        });
      }
    }

    if (fullScopeApps.length === 0 && infiniteTokenApps.length === 0) {
      findings.push({
        id: 'connected-app-scope-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No connected apps grant Full scope or use infinite refresh tokens',
        detail: `All ${apps.length} connected app(s) use scoped OAuth permissions and bounded token lifetimes.`,
        remediation: 'Periodically review connected app OAuth scopes and token policies as new apps are added.',
      });
    }

    return { findings };
  }
}
