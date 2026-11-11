import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// OauthOidcSettings states the username-password flow as blockOAuthUnPwFlow. It has no Device
// Flow field: Device Flow is switched on per connected app ("Enable for Device Flow"), and
// ConnectedApp metadata does not carry that setting either, so this check does not report it.
interface OauthOidcSettingsMeta {
  blockOAuthUnPwFlow?: boolean | string;
}

/** Settings types outside jsforce's schema come back with string values. */
function asBoolean(v: unknown): boolean | undefined {
  if (v === true || v === 'true') return true;
  if (v === false || v === 'false') return false;
  return undefined;
}

export class OauthDeviceAndAssetTokenFlowsCheck implements SecurityCheck {
  readonly id = 'oauth-device-and-asset-token-flows';
  readonly name = 'OAuth Username-Password Flow';
  readonly category = 'Identity & Access';
  readonly description =
    'Flags the OAuth 2.0 Username-Password Flow when OAuth and OpenID Connect Settings do not block it.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const oauthUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/OauthOidcSettings/home`;

    // Org settings are the only evidence read. The flow counts as blocked or not only when the
    // read returned the field as a boolean: a failed read, an absent Metadata client or a missing
    // field is not "blocked".
    let settings: OauthOidcSettingsMeta | null = null;
    if (ctx.metadata) {
      try {
        settings = await ctx.metadata.read<OauthOidcSettingsMeta>('OauthOidcSettings', 'OauthOidc');
      } catch {
        settings = null;
      }
    }
    const blocked = asBoolean(settings?.blockOAuthUnPwFlow);

    if (blocked === false) {
      findings.push({
        id: 'oauth-password-flow-enabled',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'OAuth 2.0 Username-Password Flow is not blocked in org settings',
        detail:
          'The Resource Owner Password Credentials (ROPC / Username-Password) flow allows exchanging raw credentials directly for access tokens, completely bypassing interactive SSO redirects, browser-based MFA, and device trust policies.',
        remediation:
          'Turn on "Block OAuth Username-Password Flows" in Setup → OAuth and OpenID Connect Settings, and migrate integrations to OAuth 2.0 Client Credentials or JWT Bearer flow.',
        affectedItems: [
          {
            label: 'OAuth and OpenID Connect Settings',
            url: oauthUrl,
            note: 'Block OAuth Username-Password Flows',
          },
        ],
      });
    } else if (blocked === true) {
      findings.push({
        id: 'oauth-device-and-asset-flows-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'OAuth Username-Password Flow is blocked org-wide',
        detail:
          'OAuth and OpenID Connect Settings block the Username-Password Flow, so no connected app can exchange a raw password for a token. Device Flow is switched on per connected app ("Enable for Device Flow"), and connected app metadata does not report it, so review it in each app that needs it.',
        remediation: 'Keep the Username-Password Flow blocked, and enable Device Flow only on connected apps for headless devices.',
      });
    } else {
      findings.push({
        id: 'oauth-device-and-asset-flows-advisory',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Verify the OAuth Username-Password Flow setting manually',
        detail:
          'This run could not read whether OAuth and OpenID Connect Settings block the Username-Password Flow, so whether it is allowed is unknown. The flow lets a token be issued for a raw password, bypassing MFA and conditional access.',
        remediation:
          'In Setup → OAuth and OpenID Connect Settings, confirm "Block OAuth Username-Password Flows" is on unless a documented integration needs the flow.',
        affectedItems: [{ label: 'OAuth and OpenID Connect Settings', url: oauthUrl }],
      });
    }

    return { findings };
  }
}
