import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { AuditCache } from '../../context/AuditCache.js';

const PASSWORD_SETTINGS = [
  'MinimumPasswordLength', 'PasswordComplexity', 'PasswordExpiration',
  'PasswordHistory', 'MaximumInvalidLoginAttempts', 'LockoutInterval',
  'PasswordQuestion',
];

const SESSION_SETTINGS = [
  'SessionTimeout', 'SessionSecurity', 'ClickjackProtection',
  'ContentSniffingProtection', 'CSRFProtection', 'ForceReauth',
];

const MFA_SETTINGS = [
  'RequireMfa', 'MfaRequired', 'MultiFactorAuthentication',
  'MultiFactorAuthenticationForUiLogins',
];

function matchesList(setting: string, keywords: string[]): boolean {
  const lower = setting.toLowerCase();
  return keywords.some((kw) => lower.includes(kw.toLowerCase()));
}

export class PasswordSessionPolicyCheck implements SecurityCheck {
  readonly id = 'password-session-policy';
  readonly name = 'Password and Session Policy';
  readonly category = 'Identity & Access';
  readonly dependsOnCache: ReadonlyArray<keyof AuditCache> = ['healthCheckRisks'];

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    const risks = ctx.cache.healthCheckRisks;

    if (!risks || risks.length === 0) {
      findings.push({
        id: 'password-session-policy-no-data',
        category: this.category,
        riskLevel: 'INFO',
        title: 'Password and session policy analysis requires Health Check data',
        detail:
          'No Health Check risk data was available in the cache. The HealthCheckCheck may have failed or this org may not have Health Check access.',
        remediation:
          'Run the Security Health Check in Setup → Security Center and ensure the running user has the Security Health Check permission.',
      });
      return { findings };
    }

    const passwordRisks = risks.filter((r) => matchesList(r.setting, PASSWORD_SETTINGS));
    const sessionRisks = risks.filter((r) => matchesList(r.setting, SESSION_SETTINGS));
    const mfaRisks = risks.filter((r) => matchesList(r.setting, MFA_SETTINGS));

    if (passwordRisks.length > 0) {
      findings.push({
        id: 'password-policy-failures',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${passwordRisks.length} password policy setting(s) do not meet security recommendations`,
        affectedItems: passwordRisks.map((r) => `${r.setting}: current=${r.value}`),
        detail:
          'Password policy settings deviate from CIS Salesforce Benchmark recommendations. Weak password policies increase the risk of credential-based attacks.',
        remediation:
          'Review each flagged password policy setting in Setup → Security Controls → Password Policies and align with CIS benchmarks.',
      });
    }

    if (sessionRisks.length > 0) {
      findings.push({
        id: 'session-security-deviations',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${sessionRisks.length} session security setting(s) need attention`,
        affectedItems: sessionRisks.map((r) => `${r.setting}: current=${r.value}`),
        detail:
          'Session security settings deviate from recommended values. This can expose users to session hijacking or cross-site request forgery attacks.',
        remediation:
          'Review session security settings in Setup → Security Controls → Session Settings.',
      });
    }

    if (mfaRisks.length > 0) {
      findings.push({
        id: 'mfa-gaps',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'Multi-factor authentication is not fully enforced',
        affectedItems: mfaRisks.map((r) => `${r.setting}: current=${r.value}`),
        detail:
          'MFA enforcement protects against credential-based attacks. Gaps in MFA policy leave accounts vulnerable even if passwords are compromised.',
        remediation:
          'Enable MFA for all users in Setup → Identity → Multi-Factor Authentication. Use Salesforce Authenticator or a compatible authenticator app.',
      });
    }

    if (passwordRisks.length === 0 && sessionRisks.length === 0 && mfaRisks.length === 0) {
      findings.push({
        id: 'password-session-policy-compliant',
        category: this.category,
        riskLevel: 'LOW',
        title: 'Password and session policies appear compliant with security recommendations',
        detail:
          'No password, session, or MFA-related deviations were detected in the Security Health Check results.',
        remediation:
          'Continue monitoring password policies and MFA enforcement as Salesforce releases new security recommendations.',
      });
    }

    return { findings };
  }
}
