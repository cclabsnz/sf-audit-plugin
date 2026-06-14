import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { MfaRegistration } from '../../context/AuditCache.js';

const PHISHING_RESISTANT = new Set(['U2F', 'FIDO2', 'WEBAUTHN', 'BUILT_IN_AUTHENTICATOR']);
const STRONG = new Set(['TOTP', 'SALESFORCE_AUTHENTICATOR']);
const WEAK = new Set(['EMAIL', 'VERIFICATIONCODE', 'SMS_OTP']);

type MethodStrength = 'PHISHING_RESISTANT' | 'STRONG' | 'WEAK' | 'UNKNOWN';

function strongestMethod(methods: string[]): MethodStrength {
  if (methods.some((m) => PHISHING_RESISTANT.has(m))) return 'PHISHING_RESISTANT';
  if (methods.some((m) => STRONG.has(m))) return 'STRONG';
  if (methods.some((m) => WEAK.has(m))) return 'WEAK';
  return 'UNKNOWN';
}

function isAdminProfile(profileName: string): boolean {
  const lower = profileName.toLowerCase();
  return lower.includes('admin') || lower.includes('system administrator');
}

export class MfaMethodStrengthCheck implements SecurityCheck {
  readonly id = 'mfa-method-strength';
  readonly name = 'MFA Method Strength';
  readonly category = 'Authentication';
  readonly description =
    `Classifies registered MFA methods by strength (phishing-resistant / TOTP / weak) using Salesforce's guidance and NIST; flags admin users with weak-only methods`;

  readonly dependsOnCache = ['mfaRegistrations'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/SetupOneIdEntityManagement/home`;

    const registrations: MfaRegistration[] = ctx.cache.mfaRegistrations ?? [];

    if (registrations.length === 0) {
      findings.push({
        id: 'mfa-no-data',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'No MFA registration data available — MfaRegistrationCheck must run first',
        detail:
          'The mfaRegistrations cache is empty. Either MfaRegistrationCheck did not run, or TwoFactorInfo was not accessible. MFA method strength analysis cannot be performed without this data.',
        remediation:
          'Ensure MfaRegistrationCheck runs before this check. Grant "Manage Multi-Factor Authentication in API" permission to the audit user.',
      });
      return { findings };
    }

    let phishingResistantCount = 0;
    let strongCount = 0;
    let weakOnlyCount = 0;
    const adminWeakUsers: MfaRegistration[] = [];
    const nonAdminWeakUsers: MfaRegistration[] = [];

    for (const reg of registrations) {
      const strength = strongestMethod(reg.methods);
      if (strength === 'PHISHING_RESISTANT') {
        phishingResistantCount += 1;
      } else if (strength === 'STRONG') {
        strongCount += 1;
      } else if (strength === 'WEAK' || strength === 'UNKNOWN') {
        weakOnlyCount += 1;
        if (isAdminProfile(reg.profileName)) {
          adminWeakUsers.push(reg);
        } else {
          nonAdminWeakUsers.push(reg);
        }
      }
    }

    findings.push({
      id: 'mfa-methods-summary',
      category: this.category,
      riskLevel: 'INFO',
      title: `MFA method summary: ${phishingResistantCount} phishing-resistant, ${strongCount} TOTP/authenticator, ${weakOnlyCount} weak-only`,
      detail:
        `Of ${registrations.length} user(s) with registered MFA methods: ${phishingResistantCount} use phishing-resistant methods (FIDO2/passkeys/WebAuthn, supported since Salesforce Winter 2024); ${strongCount} use TOTP or Salesforce Authenticator; ${weakOnlyCount} use only weak methods (email, SMS, or verification code). Phishing-resistant methods cannot be intercepted via real-time phishing attacks, making them the strongest option per NIST SP 800-63B and Salesforce's own MFA guidance.`,
      remediation:
        'Encourage adoption of phishing-resistant MFA methods (FIDO2 security keys, passkeys, or the Salesforce Authenticator built-in biometric) for all users. Prioritise admin-profile users.',
    });

    if (adminWeakUsers.length > 0) {
      findings.push({
        id: 'mfa-admin-weak-methods',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${adminWeakUsers.length} admin-profile user(s) rely on weak MFA methods only (email or SMS)`,
        detail:
          'Admin-profile users with only weak MFA methods (email verification codes, SMS OTP) are high-value targets. Email-based and SMS-based MFA codes can be intercepted via phishing, SIM-swapping, or email account compromise. An attacker who compromises the email inbox or phone number of an admin can bypass MFA entirely and gain full administrative access to the Salesforce org.',
        remediation:
          `Require all admin-profile users to register a phishing-resistant MFA method (FIDO2 security key, passkey, or built-in biometric authenticator) or at minimum a TOTP authenticator app (Salesforce Authenticator, Google Authenticator, Authy). Remove email-based MFA as the sole option for privileged users. Consider enforcing a minimum method strength via Salesforce's High Assurance session policy.`,
        affectedItems: adminWeakUsers.map((u) => ({
          label: u.username,
          url: setupUrl,
          note: `profile: ${u.profileName} — methods: ${u.methods.join(', ') || 'none'}`,
        })),
      });
    }

    if (nonAdminWeakUsers.length > 0) {
      findings.push({
        id: 'mfa-weak-only-users',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${nonAdminWeakUsers.length} non-admin user(s) rely on weak MFA methods only`,
        detail:
          'Non-admin users with only weak MFA methods (email verification, SMS OTP) have MFA that can be bypassed via phishing or SIM-swapping. While the risk is lower than for admin users, these users can still access sensitive CRM data and their accounts can be used to exfiltrate information or as a pivot point for privilege escalation.',
        remediation:
          'Encourage all users to upgrade to TOTP authenticator apps or phishing-resistant methods. Communicate the risks of email-based and SMS-based MFA to end users. Consider providing security keys or passkey onboarding guidance as part of your security awareness programme.',
        affectedItems: nonAdminWeakUsers.slice(0, 30).map((u) => ({
          label: u.username,
          url: setupUrl,
          note: `profile: ${u.profileName} — methods: ${u.methods.join(', ') || 'none'}`,
        })),
      });
    }

    const phishingResistantPct =
      registrations.length > 0 ? (phishingResistantCount / registrations.length) * 100 : 0;

    if (phishingResistantPct > 50) {
      findings.push({
        id: 'mfa-phishing-resistant-users',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${phishingResistantCount} of ${registrations.length} user(s) (${Math.round(phishingResistantPct)}%) use phishing-resistant MFA`,
        detail:
          `More than half of registered users use phishing-resistant MFA methods (FIDO2, WebAuthn, passkeys, or built-in biometric authenticators), which are supported since Salesforce Winter 2024. Phishing-resistant methods cannot be intercepted by real-time phishing proxies, providing the strongest available protection against credential theft.`,
        remediation:
          'Continue to drive phishing-resistant MFA adoption for remaining users. Target 100% coverage for admin-profile users as a priority.',
      });
    }

    return { findings };
  }
}
