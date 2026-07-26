import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OrgRecord {
  MyDomain: string | null;
  IsSandbox: boolean;
}

interface AuthConfigRecord {
  DeveloperName: string;
  AuthOptionsSaml: boolean;
  AuthOptionsUsernamePassword: boolean;
  IsDisabled: boolean;
}

export class MyDomainLoginPolicyCheck implements SecurityCheck {
  readonly id = 'my-domain-login-policy';
  readonly name = 'My Domain Login Policy';
  readonly category = 'Authentication';
  readonly description = 'Checks that My Domain is configured and login from login.salesforce.com is prevented: stops SSO bypass';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const ssoSetupUrl = `${baseUrl}/lightning/setup/SingleSignOn/home`;
    const domainSetupUrl = `${baseUrl}/lightning/setup/MyDomain/home`;

    // Q1 (SOQL): check if My Domain is configured
    const orgResult = await ctx.soql.query<OrgRecord>(
      `SELECT MyDomain, IsSandbox FROM Organization LIMIT 1`
    );
    const org = orgResult.records[0];
    const myDomain = org?.MyDomain ?? null;
    const isSandbox = org?.IsSandbox ?? false;

    if (!myDomain) {
      findings.push({
        id: 'my-domain-not-configured',
        category: this.category,
        riskLevel: isSandbox ? 'MEDIUM' : 'HIGH',
        title: 'My Domain is not configured',
        detail:
          `My Domain is required to enforce SSO and to control the login experience. Without My Domain, users can authenticate directly via \`login.salesforce.com\` bypassing any identity provider restrictions. My Domain is also a prerequisite for Lightning Experience, SSO, and Enhanced Domains.`,
        remediation:
          'Configure My Domain in Setup → My Domain. After deployment, set the login policy to "Prevent login from login.salesforce.com" to ensure all logins go through your identity provider.',
        affectedItems: [{ label: 'My Domain Setup', url: domainSetupUrl, note: 'My Domain not configured: required for SSO enforcement' }],
      });
      return { findings };
    }

    findings.push({
      id: 'my-domain-configured',
      category: this.category,
      riskLevel: 'INFO',
      title: `My Domain configured: ${myDomain}`,
      detail: `The org has a custom My Domain (${myDomain}) configured, which is a prerequisite for SSO enforcement and Enhanced Domains.`,
      remediation: 'Verify the login policy in Setup → My Domain prevents login from login.salesforce.com.',
    });

    // Q2 (Tooling): check AuthConfig for login options.
    // If AuthOptionsUsernamePassword is false in the AuthConfig for the org domain,
    // users cannot log in with Salesforce credentials — they must go through SSO.
    try {
      const authConfigs = await ctx.tooling.query<AuthConfigRecord>(
        `SELECT DeveloperName, AuthOptionsSaml, AuthOptionsUsernamePassword, IsDisabled
         FROM AuthConfig
         WHERE IsDisabled = false`
      );

      if (authConfigs.length === 0) {
        findings.push({
          id: 'my-domain-auth-config-empty',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: 'No active AuthConfig found: My Domain login policy unverified',
          detail:
            'The My Domain login policy (which controls whether users can log in with Salesforce credentials or must use SSO) could not be read from AuthConfig. The login policy may allow credential-based login even when SSO is configured.',
          remediation:
            'Manually verify in Setup → My Domain → Authentication Configuration that "Prevent Login from login.salesforce.com" is enabled.',
          affectedItems: [{ label: myDomain, url: domainSetupUrl, note: 'Verify authentication configuration manually' }],
        });
      } else {
        // An AuthConfig where AuthOptionsUsernamePassword = true means password login is allowed
        const passwordAllowed = authConfigs.filter((c) => c.AuthOptionsUsernamePassword);
        const ssoEnforced = authConfigs.filter(
          (c) => !c.AuthOptionsUsernamePassword && c.AuthOptionsSaml
        );

        if (passwordAllowed.length > 0) {
          findings.push({
            id: 'my-domain-password-login-allowed',
            category: this.category,
            riskLevel: 'HIGH',
            title: 'My Domain allows username-password login: SSO not enforced',
            detail:
              `The AuthConfig for this org allows users to log in with Salesforce username and password, meaning SSO via your identity provider is not the only authentication path. Users can bypass SSO (and its MFA, conditional access, and session controls) by using direct credentials. Affected authentication configuration(s): ${passwordAllowed.map((c) => c.DeveloperName).join(', ')}.`,
            remediation:
              'In Setup → My Domain → Authentication Configuration, disable "Login Page" (Salesforce credentials) as an authentication option. Ensure SAML/SSO is the only allowed method. Also enable "Prevent Login from login.salesforce.com" in My Domain settings.',
            affectedItems: passwordAllowed.map((c) => ({
              label: c.DeveloperName,
              url: domainSetupUrl,
              note: 'AuthOptionsUsernamePassword = true: disable password login to enforce SSO',
            })),
          });
        }

        if (ssoEnforced.length > 0 && passwordAllowed.length === 0) {
          findings.push({
            id: 'my-domain-sso-enforced',
            category: this.category,
            riskLevel: 'LOW',
            passed: true,
            title: 'My Domain is configured to require SSO: password login disabled',
            detail:
              `The AuthConfig for this org has SAML enabled and password login disabled, indicating SSO is enforced via My Domain. Users cannot log in with Salesforce credentials. They must authenticate through the configured identity provider.`,
            remediation: 'Verify that the SAML configuration points to the correct identity provider and that the IdP enforces MFA.',
            affectedItems: ssoEnforced.map((c) => ({
              label: c.DeveloperName,
              url: ssoSetupUrl,
              note: 'SAML only: password login disabled',
            })),
          });
        }
      }
    } catch {
      findings.push({
        id: 'my-domain-auth-config-inaccessible',
        category: this.category,
        riskLevel: 'MEDIUM',
        inconclusive: true,
        title: 'My Domain login policy could not be verified: AuthConfig not accessible',
        detail:
          'The Tooling API AuthConfig query was not accessible. The My Domain login policy (credential login vs SSO-only) cannot be automatically verified.',
        remediation:
          'Manually verify in Setup → My Domain → Authentication Configuration that "Login Page" is disabled and "Prevent Login from login.salesforce.com" is enabled.',
      });
    }

    return { findings };
  }
}
