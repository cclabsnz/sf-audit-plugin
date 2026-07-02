import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AuthProviderRec {
  Id: string;
  DeveloperName: string;
  ProviderType: string;
  FriendlyName: string | null;
}
interface SamlConfigRec {
  Id: string;
  DeveloperName: string;
  Issuer: string | null;
}

// Consumer/social identity providers — higher risk when they can create users
// via just-in-time provisioning, because an attacker-controlled account at the
// provider becomes an org login.
const SOCIAL_TYPES = new Set(['Facebook', 'Google', 'Twitter', 'LinkedIn', 'GitHub', 'OpenIdConnect']);

/**
 * Reviews external identity federation — Auth Providers and SAML SSO configs.
 * Every configured provider is a way into the org that does not use a Salesforce
 * password, so an unvetted or misconfigured provider (especially social login with
 * just-in-time user creation) can let attackers federate in or auto-provision
 * over-privileged users.
 */
export class AuthProvidersCheck implements SecurityCheck {
  readonly id = 'auth-providers';
  readonly name = 'Auth Providers & External IdPs';
  readonly category = 'Authentication';
  readonly description =
    'Reviews configured Auth Providers and SAML SSO configurations — external login paths that bypass Salesforce credentials and can auto-provision users';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let providers: AuthProviderRec[] = [];
    let providersFailed = false;
    try {
      providers = await ctx.soql.queryAll<AuthProviderRec>('SELECT Id, DeveloperName, ProviderType, FriendlyName FROM AuthProvider');
    } catch {
      providersFailed = true;
    }

    let saml: SamlConfigRec[] = [];
    try {
      saml = await ctx.soql.queryAll<SamlConfigRec>('SELECT Id, DeveloperName, Issuer FROM SamlSsoConfig');
    } catch {
      // SAML config not accessible / not configured — handled together with providers below.
    }

    if (providersFailed) {
      findings.push({
        id: 'auth-providers-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Auth Providers could not be queried (insufficient access)',
        detail: 'The AuthProvider object was not accessible, so external identity federation could not be evaluated.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run. Also review Setup → Auth. Providers and Single Sign-On Settings manually.',
      });
      return { findings };
    }

    const social = providers.filter((p) => SOCIAL_TYPES.has(p.ProviderType));

    if (social.length > 0) {
      findings.push({
        id: 'auth-providers-social',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${social.length} social/consumer Auth Provider(s) configured`,
        detail:
          'Social and OpenID Connect auth providers let users authenticate with external consumer identities. If the registration handler provisions users just-in-time, an attacker who controls (or creates) an account at the provider may obtain an org login — potentially with a default profile that is more privileged than intended.',
        remediation:
          'Confirm each social provider is intentional, review its Apex registration handler for least-privilege user creation (and that it does not auto-activate high-privilege profiles), and disable providers that are not required.',
        affectedItems: social.map((p) => ({ label: `${p.FriendlyName ?? p.DeveloperName} (${p.ProviderType})`, url: `${baseUrl}/lightning/setup/AuthProviders/home` })),
      });
    }

    const nonSocial = providers.filter((p) => !SOCIAL_TYPES.has(p.ProviderType));
    if (nonSocial.length > 0 || saml.length > 0) {
      findings.push({
        id: 'auth-providers-inventory',
        category: this.category,
        riskLevel: 'INFO',
        title: `${nonSocial.length} other Auth Provider(s) and ${saml.length} SAML SSO config(s) configured`,
        detail:
          'These external identity paths let users sign in without a Salesforce password. Each SAML config and enterprise auth provider should be a known, trusted IdP with certificate validation and no stale/duplicate entries.',
        remediation:
          'Review each SAML SSO config (Issuer, signing certificate, and that "Just-in-time provisioning" creates least-privilege users) and each auth provider. Remove any that are unused or unrecognised.',
        affectedItems: [
          ...nonSocial.map((p) => ({ label: `Auth Provider: ${p.FriendlyName ?? p.DeveloperName} (${p.ProviderType})`, url: `${baseUrl}/lightning/setup/AuthProviders/home` })),
          ...saml.map((s) => ({ label: `SAML: ${s.DeveloperName}${s.Issuer ? ` (${s.Issuer})` : ''}`, url: `${baseUrl}/lightning/setup/SingleSignOn/home` })),
        ].slice(0, 40),
      });
    }

    if (providers.length === 0 && saml.length === 0) {
      findings.push({
        id: 'auth-providers-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No external Auth Providers or SAML SSO configured',
        detail: 'No AuthProvider or SamlSsoConfig records exist, so there is no external federation surface to review.',
        remediation: 'If external identity is added later, restrict just-in-time provisioning to least-privilege profiles and validate the IdP certificate.',
      });
    }

    return { findings };
  }
}
