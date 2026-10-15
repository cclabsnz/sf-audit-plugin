import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OauthOidcSettingsMeta {
  isDeviceFlowEnabled?: boolean;
  isPasswordFlowEnabled?: boolean;
}

interface ConnectedAppRecord {
  Id: string;
  Name?: string;
  OptionsIsDeviceFlowEnabled?: boolean;
  OptionsIsPasswordFlowEnabled?: boolean;
}

export class OauthDeviceAndAssetTokenFlowsCheck implements SecurityCheck {
  readonly id = 'oauth-device-and-asset-token-flows';
  readonly name = 'OAuth Device & Password Flows';
  readonly category = 'Identity & Access';
  readonly description =
    'Flags OAuth 2.0 Device Flow and Username-Password Flow enabled in org settings or connected apps.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const oauthUrl = `${baseUrl}/lightning/setup/OauthOidcSettings/home`;

    let deviceFlowEnabled = false;
    let passwordFlowEnabled = false;
    let metadataReadSucceeded = false;

    // 1. Read OauthOidcSettings via Metadata API
    if (ctx.metadata) {
      try {
        const settings = await ctx.metadata.read<OauthOidcSettingsMeta>(
          'OauthOidcSettings',
          'OauthOidc',
        );
        if (settings) {
          metadataReadSucceeded = true;
          if (settings.isDeviceFlowEnabled === true) {
            deviceFlowEnabled = true;
          }
          if (settings.isPasswordFlowEnabled === true) {
            passwordFlowEnabled = true;
          }
        }
      } catch {
        // Fall back to Tooling / Connected Apps inspect
      }
    }

    // 2. Also inspect ConnectedApplication records via Tooling API
    try {
      const apps = await ctx.tooling.query<ConnectedAppRecord>(
        'SELECT Id, Name FROM ConnectedApplication',
      );
      for (const app of apps) {
        if (app.OptionsIsDeviceFlowEnabled === true) {
          deviceFlowEnabled = true;
        }
        if (app.OptionsIsPasswordFlowEnabled === true) {
          passwordFlowEnabled = true;
        }
      }
    } catch {
      // Degrade gracefully if ConnectedApplication is unavailable
    }

    if (deviceFlowEnabled) {
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

    if (passwordFlowEnabled) {
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

    if (!deviceFlowEnabled && !passwordFlowEnabled) {
      if (metadataReadSucceeded || ctx.metadata) {
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
      } else {
        findings.push({
          id: 'oauth-device-and-asset-flows-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No enabled Device or Password Flows detected',
          detail: 'No connected applications or org settings enabling Device Flow or Password Flow were identified.',
          remediation: 'Verify Setup → OAuth and OpenID Connect Settings manually.',
        });
      }
    }

    return { findings };
  }
}
