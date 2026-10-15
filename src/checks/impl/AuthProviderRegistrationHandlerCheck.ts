import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AuthProviderRecord {
  Id: string;
  DeveloperName: string;
  FriendlyName: string;
  ProviderType: string;
  ExecutionUserId?: string | null;
  RegistrationHandlerId?: string | null;
}

interface UserRecord {
  Id: string;
  Username: string;
  IsActive: boolean;
  Profile?: { Name?: string };
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body?: string | null;
}

export class AuthProviderRegistrationHandlerCheck implements SecurityCheck {
  readonly id = 'auth-provider-registration-handler';
  readonly name = 'Auth.Provider Registration Handler Security';
  readonly category = 'Identity & Access';
  readonly description =
    'Detects Auth.Provider RegistrationHandler running as Admin with email-based account linking vulnerable to pre-auth takeover.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const authProviderUrl = `${baseUrl}/lightning/setup/AuthProviders/home`;

    let providers: AuthProviderRecord[] = [];
    try {
      providers = await ctx.soql.queryAll<AuthProviderRecord>(
        'SELECT Id, DeveloperName, FriendlyName, ProviderType, ExecutionUserId, RegistrationHandlerId FROM AuthProvider WHERE RegistrationHandlerId != null',
      );
    } catch (err) {
      // This object exists in every org, so a failure is lack of access, never an absent feature.
      findings.push({
        id: 'auth-provider-registration-handler-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Auth Providers could not be queried',
        detail: `Failed to query AuthProvider: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "View Setup and Configuration".',
      });
      return { findings };
    }

    if (providers.length === 0) {
      findings.push({
        id: 'auth-provider-registration-handler-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Auth Providers configured with Registration Handlers',
        detail: 'Zero AuthProvider records in this org configure an automated Registration Handler.',
        remediation: 'When configuring Registration Handlers, avoid execution as System Administrator and verify email authenticity.',
      });
      return { findings };
    }

    // Query Execution Users
    const executionUserIds = [
      ...new Set(providers.map((p) => p.ExecutionUserId).filter((id): id is string => Boolean(id))),
    ];
    let adminUsers = new Set<string>();
    let userDetails = new Map<string, string>();

    if (executionUserIds.length > 0) {
      const users = await ctx.soql.queryAll<UserRecord>(
        `SELECT Id, Username, IsActive, Profile.Name FROM User WHERE Id IN ('${executionUserIds.join("','")}')`,
      );
      for (const u of users) {
        const profName = u.Profile?.Name ?? '';
        userDetails.set(u.Id, `${u.Username} (${profName})`);
        if (profName === 'System Administrator' || profName.toLowerCase().includes('admin')) {
          adminUsers.add(u.Id);
        }
      }
    }

    // Query Registration Handler Apex classes
    const handlerIds = [
      ...new Set(providers.map((p) => p.RegistrationHandlerId).filter((id): id is string => Boolean(id))),
    ];
    let classBodies = new Map<string, string>();
    let classNames = new Map<string, string>();

    if (handlerIds.length > 0) {
      const classes = await ctx.soql.queryAll<ApexClassRecord>(
        `SELECT Id, Name, Body FROM ApexClass WHERE Id IN ('${handlerIds.join("','")}')`,
      );
      for (const c of classes) {
        classNames.set(c.Id, c.Name);
        classBodies.set(c.Id, c.Body ?? '');
      }
    }

    const adminExecProviders: AuthProviderRecord[] = [];
    const unverifiedEmailLinkingProviders: AuthProviderRecord[] = [];

    for (const p of providers) {
      const isExecAdmin = p.ExecutionUserId && adminUsers.has(p.ExecutionUserId);
      if (isExecAdmin) {
        adminExecProviders.push(p);
      }

      const body = p.RegistrationHandlerId ? classBodies.get(p.RegistrationHandlerId) ?? '' : '';
      if (body) {
        // Check if class queries user by email
        const matchesEmailQuery = /SELECT\s+[^;]+FROM\s+User\s+WHERE\s+[^;]*Email\s*=/i.test(body);
        // Check if verification or portal scoping is present
        const checksVerified = /email_verified|isEmailVerified|emailVerified/i.test(body);
        const checksPortalScope = /UserType|IsPortalEnabled|UserLicense/i.test(body);

        if (matchesEmailQuery && (!checksVerified || !checksPortalScope)) {
          unverifiedEmailLinkingProviders.push(p);
        }
      }
    }

    if (adminExecProviders.length > 0) {
      findings.push({
        id: 'auth-provider-registration-handler-admin-exec',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${adminExecProviders.length} Auth Provider(s) execute Registration Handler as System Administrator`,
        detail:
          'When an Auth.Provider (SSO, OIDC, Google, etc.) Registration Handler runs under a System Administrator execution context, any user creation, role assignment, or record linking executed by the handler occurs with maximum system privileges, enabling automated privilege escalation.',
        remediation:
          'Configure the "Execute Registration As" user to a dedicated least-privileged integration user rather than a full System Administrator.',
        affectedItems: adminExecProviders.map((p) => ({
          label: p.FriendlyName || p.DeveloperName,
          url: authProviderUrl,
          note: `Execution user: ${p.ExecutionUserId ? userDetails.get(p.ExecutionUserId) ?? p.ExecutionUserId : 'Unknown'}`,
        })),
      });
    }

    if (unverifiedEmailLinkingProviders.length > 0) {
      findings.push({
        id: 'auth-provider-registration-handler-unverified-email-linking',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${unverifiedEmailLinkingProviders.length} Auth Provider(s) link user accounts by email without verification or portal scoping`,
        detail:
          'The RegistrationHandler Apex class matches existing User records purely by email address (SELECT Id FROM User WHERE Email = :data.email) without validating email verification tokens (email_verified == true) or scoping to portal user types. An attacker registering an account with a target admin\'s email address on a public or social identity provider can hijack the internal admin user account upon login.',
        remediation:
          'Update the RegistrationHandler to verify email_verified == true from the identity provider and ensure social/external registrations can never match internal standard or administrator User records.',
        affectedItems: unverifiedEmailLinkingProviders.map((p) => ({
          label: `${p.FriendlyName || p.DeveloperName} (Handler: ${p.RegistrationHandlerId ? classNames.get(p.RegistrationHandlerId) ?? p.RegistrationHandlerId : 'Unknown'})`,
          url: authProviderUrl,
          note: 'Unverified email matching against User table',
        })),
      });
    }

    if (adminExecProviders.length === 0 && unverifiedEmailLinkingProviders.length === 0) {
      findings.push({
        id: 'auth-provider-registration-handler-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Auth Provider Registration Handlers are securely configured',
        detail: `${providers.length} Auth Provider(s) inspected; handlers do not run as System Administrator and do not perform unverified email account linking.`,
        remediation: 'Continue enforcing least-privilege execution users and strict identity verification in Registration Handlers.',
      });
    }

    return { findings };
  }
}
