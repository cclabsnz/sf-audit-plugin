import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { hasField } from '../support/schema.js';

// "Is Single Sign-On Enabled". Salesforce adds this permission field only to orgs where it has
// enabled delegated authentication; without the field no profile can route sign-in through a
// delegated gateway. It is the only delegated-auth signal the check can read: the Metadata API
// SingleSignOnSettings documents enableForceDelegateCallout but no "enabled" flag or gateway URL,
// so the gateway itself has to be checked by hand.
// https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_securitysettings.htm
const SSO_PERMISSION = 'PermissionsIsSsoEnabled';

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
    'Flags Delegated Authentication assigned to administrator profiles, and asks for the gateway to be verified where Delegated Authentication is available.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const ssoUrl = `${baseUrl}/lightning/setup/SingleSignOn/home`;

    if (!(await hasField(ctx, 'Profile', SSO_PERMISSION))) {
      findings.push({
        id: 'delegated-authentication-exposure-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Delegated Authentication is not available in this org',
        detail:
          'The "Is Single Sign-On Enabled" permission does not exist in this org. Salesforce adds it only when it enables Delegated Authentication, so no sign-in can be routed through a delegated gateway.',
        remediation: 'Continue using SAML 2.0 or OpenID Connect with signed assertions for SSO.',
      });
      return { findings };
    }

    const profiles = await ctx.soql.queryAll<ProfileRecord>(
      `SELECT Id, Name, ${SSO_PERMISSION} FROM Profile WHERE ${SSO_PERMISSION} = true`,
    );
    const adminProfiles = profiles.filter(
      (p) => p.Name.toLowerCase().includes('admin') || p.Name === 'System Administrator',
    );

    if (adminProfiles.length > 0) {
      findings.push({
        id: 'delegated-authentication-admin-assigned',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `Delegated Authentication is assigned to ${adminProfiles.length} Administrator profile(s)`,
        detail:
          'The "Is Single Sign-On Enabled" permission routes user authentication through the external delegated gateway. When assigned to System Administrators, compromising or spoofing the delegated gateway grants instantaneous full org takeover as an admin.',
        remediation:
          'Remove "Is Single Sign-On Enabled" from System Administrator and privileged profiles. Reserve Delegated Authentication strictly for standard users, or enforce SAML/OIDC.',
        affectedItems: adminProfiles.map((p) => ({
          label: p.Name,
          url: `${baseUrl}/lightning/setup/EnhancedProfiles/page?address=%2F${p.Id}`,
          note: 'Admin profile routes authentication through delegated gateway',
        })),
      });
    }

    findings.push({
      id: 'delegated-authentication-advisory',
      category: this.category,
      riskLevel: 'INFO',
      title: 'Delegated Authentication is available: verify the gateway by hand',
      detail: `Salesforce has enabled Delegated Authentication in this org, and ${profiles.length} profile(s) hold "Is Single Sign-On Enabled". The gateway URL is not exposed through a documented API, so this audit cannot check it. Delegated Authentication trusts a plain SOAP true or false from the gateway, with no signed assertion.`,
      remediation:
        'In Setup → Single Sign-On Settings, confirm the Delegated Gateway URL uses HTTPS, ideally with mutual TLS, or move to SAML 2.0 / OpenID Connect.',
      affectedItems: [{ label: 'Single Sign-On Settings', url: ssoUrl }],
    });

    return { findings };
  }
}
