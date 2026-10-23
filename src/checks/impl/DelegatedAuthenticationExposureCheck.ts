import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { hasField } from '../support/schema.js';

// "Is Single Sign-On Enabled". Salesforce adds this permission field only to orgs where it has
// enabled delegated authentication; without the field no profile can route sign-in through a
// delegated gateway.
const SSO_PERMISSION = 'PermissionsIsSsoEnabled';

interface SecuritySettingsMeta {
  singleSignOnSettings?: {
    isDelegatedAuthEnabled?: boolean;
    delegatedGatewayUrl?: string;
  };
}

interface ProfileRecord {
  Id: string;
  Name: string;
  PermissionsIsSsoEnabled?: boolean;
}

export class DelegatedAuthenticationExposureCheck implements SecurityCheck {
  readonly id = 'delegated-authentication-exposure';
  readonly name = 'Delegated Authentication Exposure';
  readonly category = 'Identity & Access';
  readonly description =
    'Flags Delegated Authentication enabled over non-mTLS endpoints or assigned to System Administrator profiles.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const ssoUrl = `${baseUrl}/lightning/setup/SingleSignOn/home`;

    // Enabled, disabled, or unknown. Only a boolean actually returned by the settings read
    // decides; a failed read or an absent Metadata client leaves it unknown, never "disabled".
    let delegatedAuth: boolean | undefined;
    let gatewayUrl = '';
    if (ctx.metadata) {
      try {
        const sec = await ctx.metadata.read<SecuritySettingsMeta>('SecuritySettings', 'Security');
        const sso = sec?.singleSignOnSettings;
        if (typeof sso?.isDelegatedAuthEnabled === 'boolean') {
          delegatedAuth = sso.isDelegatedAuthEnabled;
          gatewayUrl = sso.delegatedGatewayUrl ?? '';
        }
      } catch {
        delegatedAuth = undefined;
      }
    }
    const isDelegatedAuthEnabled = delegatedAuth === true;

    const profiles = (await hasField(ctx, 'Profile', SSO_PERMISSION))
      ? await ctx.soql.queryAll<ProfileRecord>(
          `SELECT Id, Name, ${SSO_PERMISSION} FROM Profile WHERE ${SSO_PERMISSION} = true`,
        )
      : [];
    const adminProfilesWithDelegatedAuth = profiles.filter(
      (p) => p.Name.toLowerCase().includes('admin') || p.Name === 'System Administrator',
    );

    if (isDelegatedAuthEnabled) {
      // Check 1: Insecure Gateway URL (non-https or cleartext)
      const isInsecure =
        !gatewayUrl ||
        gatewayUrl.startsWith('http://') ||
        (!gatewayUrl.startsWith('https://') && gatewayUrl.length > 0);

      if (isInsecure) {
        findings.push({
          id: 'delegated-authentication-insecure-gateway',
          category: this.category,
          riskLevel: 'CRITICAL',
          title: 'Delegated Authentication gateway is unencrypted or missing mutual TLS',
          detail: `Delegated Authentication is enabled with gateway URL "${gatewayUrl || 'empty'}". Unlike SAML or OIDC, Delegated Authentication relies on a simple SOAP boolean response without cryptographic assertion signatures. Transmitting credentials over unencrypted or unauthenticated endpoints allows credential harvesting and spoofed responses.`,
          remediation:
            'Configure a secure HTTPS endpoint with mutual TLS (mTLS) client certificate verification for the Delegated Authentication gateway, or migrate to SAML 2.0 / OpenID Connect.',
          affectedItems: [
            {
              label: 'Delegated Gateway Endpoint',
              url: ssoUrl,
              note: `Gateway URL: ${gatewayUrl || 'None configured'}`,
            },
          ],
        });
      }

      // Check 2: Assigned to System Administrators
      if (adminProfilesWithDelegatedAuth.length > 0) {
        findings.push({
          id: 'delegated-authentication-admin-assigned',
          category: this.category,
          riskLevel: 'CRITICAL',
          title: `Delegated Authentication is assigned to ${adminProfilesWithDelegatedAuth.length} Administrator profile(s)`,
          detail:
            'The "Is Single Sign-On Enabled" permission routes user authentication through the external delegated gateway. When assigned to System Administrators, compromising or spoofing the delegated gateway grants instantaneous full org takeover as an admin.',
          remediation:
            'Remove "Is Single Sign-On Enabled" from System Administrator and privileged profiles. Reserve Delegated Authentication strictly for standard users, or enforce SAML/OIDC.',
          affectedItems: adminProfilesWithDelegatedAuth.map((p) => ({
            label: p.Name,
            url: `${baseUrl}/lightning/setup/EnhancedProfiles/page?address=%2F${p.Id}`,
            note: 'Admin profile routes authentication through delegated gateway',
          })),
        });
      }
    }

    if (delegatedAuth === undefined) {
      findings.push({
        id: 'delegated-authentication-advisory',
        category: this.category,
        riskLevel: 'INFO',
        title: 'Verify Delegated Authentication settings manually',
        detail: `This run could not read SecuritySettings, so whether Delegated Authentication is enabled is unknown. ${adminProfilesWithDelegatedAuth.length} administrator profile(s) hold "Is Single Sign-On Enabled", which routes their sign-in through the delegated gateway if it is on.`,
        remediation:
          'In Setup → Single Sign-On Settings, check whether Delegated Authentication is enabled. If it is, the gateway must be HTTPS with mutual TLS, and administrator profiles should not hold "Is Single Sign-On Enabled".',
        affectedItems: [{ label: 'Single Sign-On Settings', url: ssoUrl }],
      });
    } else if (findings.length === 0) {
      findings.push({
        id: 'delegated-authentication-exposure-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: isDelegatedAuthEnabled
          ? 'Delegated Authentication uses an HTTPS gateway and is not assigned to administrators'
          : 'Delegated Authentication is disabled',
        detail: isDelegatedAuthEnabled
          ? 'SecuritySettings shows Delegated Authentication enabled with an HTTPS gateway, and no administrator profile holds "Is Single Sign-On Enabled".'
          : 'SecuritySettings confirms Delegated Authentication is disabled, so no sign-in is routed through an external gateway.',
        remediation: 'Continue using SAML 2.0 or OpenID Connect with signed assertions for SSO.',
      });
    }

    return { findings };
  }
}
