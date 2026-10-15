import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OauthOidcSettingsMeta {
  isDeviceFlowEnabled?: boolean;
  isPasswordFlowEnabled?: boolean;
}

export class OauthDeviceAndAssetTokenFlowsCheck implements SecurityCheck {
  readonly id = 'oauth-device-and-asset-token-flows';
  readonly name = 'OAuth Device & Password Flows';
  readonly category = 'Identity & Access';
  readonly description =
    'Flags OAuth 2.0 Device Flow and Username-Password Flow enabled in OAuth and OpenID Connect Settings.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const oauthUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/OauthOidcSettings/home`;

    // Org settings are the only evidence read. A flag counts only when the read returned it as
    // a boolean: a failed read, an absent Metadata client or a missing field is not "disabled".
    let settings: OauthOidcSettingsMeta | null = null;
    if (ctx.metadata) {
      try {
        settings = await ctx.metadata.read<OauthOidcSettingsMeta>('OauthOidcSettings', 'OauthOidc');
      } catch {
        settings = null;
      }
    }
    const device = typeof settings?.isDeviceFlowEnabled === 'boolean' ? settings.isDeviceFlowEnabled : undefined;
    const password =
      typeof settings?.isPasswordFlowEnabled === 'boolean' ? settings.isPasswordFlowEnabled : undefined;

    if (device === true) {
      findings.push({
        id: 'oauth-device-flow-enabled',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'OAuth 2.0 Device Flow is ENABLED in org settings',
        detail:
          'OAuth 2.0 Device Flow allows a user to authorize a token by entering an 8-character code on a legitimate verification URL. Attackers frequently use Device Code phishing to bypass standard browser-based conditional access and MFA controls, obtaining persistent refresh tokens.',
        remediation:
          'Disable OAuth 2.0 Device Flow in Setup → OAuth and OpenID Connect Settings unless strictly required for headless devices.',
        affectedItems: [
          {
            label: 'OAuth and OpenID Connect Settings',
            url: oauthUrl,
            note: 'Disable "Allow OAuth Device Flow"',
          },
        ],
      });
    }

    if (password === true) {
      findings.push({
        id: 'oauth-password-flow-enabled',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'OAuth 2.0 Username-Password Flow is ENABLED in org settings',
        detail:
          'The Resource Owner Password Credentials (ROPC / Username-Password) flow allows exchanging raw credentials directly for access tokens, completely bypassing interactive SSO redirects, browser-based MFA, and device trust policies.',
        remediation:
          'Disable Username-Password Flow in Setup → OAuth and OpenID Connect Settings, and migrate integrations to OAuth 2.0 Client Credentials or JWT Bearer flow.',
        affectedItems: [
          {
            label: 'OAuth and OpenID Connect Settings',
            url: oauthUrl,
            note: 'Disable "Allow Username-Password Flow"',
          },
        ],
      });
    }

    if (device === false && password === false) {
      findings.push({
        id: 'oauth-device-and-asset-flows-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Phishable OAuth Device Flow and Username-Password Flow are disabled',
        detail:
          'Org settings confirm both OAuth 2.0 Device Flow and Username-Password Flow are disabled, eliminating secondary token-issuance backdoors.',
        remediation: 'Keep Device Flow and Password Flow disabled org-wide.',
      });
    } else if (device === undefined || password === undefined) {
      const unread = [device === undefined && 'Device Flow', password === undefined && 'Username-Password Flow']
        .filter(Boolean)
        .join(' and ');
      findings.push({
        id: 'oauth-device-and-asset-flows-advisory',
        category: this.category,
        riskLevel: 'INFO',
        title: `Verify the OAuth ${unread} setting manually`,
        detail: `This run could not read the ${unread} setting from OAuth and OpenID Connect Settings, so whether it is enabled is unknown. Both flows let a token be issued outside the browser sign-in, bypassing MFA and conditional access.`,
        remediation:
          'In Setup → OAuth and OpenID Connect Settings, confirm "Allow OAuth Device Flow" and "Allow OAuth Username-Password Flows" are off unless a documented integration needs them.',
        affectedItems: [{ label: 'OAuth and OpenID Connect Settings', url: oauthUrl }],
      });
    }

    return { findings };
  }
}
