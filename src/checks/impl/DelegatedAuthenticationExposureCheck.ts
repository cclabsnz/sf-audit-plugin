import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface SecuritySettingsMeta {
  singleSignOnSettings?: {
    isDelegatedAuthEnabled?: boolean;
    delegatedGatewayUrl?: string;
  };
}

interface ProfileRecord {
  Id: string;
  Name: string;
  PermissionsIsSingleSignOnEnabled?: boolean;
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

    let isDelegatedAuthEnabled = false;
    let gatewayUrl = '';

    if (ctx.metadata) {
      try {
        const sec = await ctx.metadata.read<SecuritySettingsMeta>(
          'SecuritySettings',
          'Security',
        );
        if (sec?.singleSignOnSettings?.isDelegatedAuthEnabled === true) {
          isDelegatedAuthEnabled = true;
          gatewayUrl = sec.singleSignOnSettings.delegatedGatewayUrl ?? '';
        }
      } catch {
        // Degrade gracefully if SecuritySettings read fails
      }
    }

    // Query profiles with IsSingleSignOnEnabled
    let adminProfilesWithDelegatedAuth: ProfileRecord[] = [];
    try {
      const profiles = await ctx.soql.queryAll<ProfileRecord>(
        'SELECT Id, Name, PermissionsIsSingleSignOnEnabled FROM Profile WHERE PermissionsIsSingleSignOnEnabled = true',
      );
      adminProfilesWithDelegatedAuth = profiles.filter(
        (p) =>
          p.Name.toLowerCase().includes('admin') ||
          p.Name === 'System Administrator',
      );
    } catch {
      // Degrade gracefully if Profile query fails
    }

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

    if (!isDelegatedAuthEnabled && adminProfilesWithDelegatedAuth.length === 0) {
      findings.push({
        id: 'delegated-authentication-exposure-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Delegated Authentication is disabled or not assigned to privileged administrators',
        detail:
          'Delegated Authentication is not enabled for privileged administrators, preventing external gateway spoofing attacks.',
        remediation: 'Continue using SAML 2.0 or OpenID Connect with signed assertions for SSO.',
      });
    }

    return { findings };
  }
}
