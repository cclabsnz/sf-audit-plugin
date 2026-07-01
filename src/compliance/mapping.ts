// Maps each check id to the compliance control ids it relates to.
// Migrated from the former ComplianceMapping. HIPAA/GDPR ids are intentionally omitted
// until their catalogs land (later plan). A08/A10 are mapped precisely:
//   A10 (SSRF) → egress controls (remote-sites, csp-trusted-sites, named-credentials)
//   A08 (Software & Data Integrity) → installed-packages, deployment-identity
// NZ pack control ids (HISO/NZISM/Privacy Act) are layered on by domain via NZ_CROSSWALK below.
const BASE_CHECK_CONTROL_MAP: Record<string, string[]> = {
  'users-and-admins':        ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-ACS-004'],
  'permissions':             ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-ACS-002', 'SBS-ACS-005'],
  'inactive-users':          ['OWASP-A01', 'SOC2-CC6.2', 'ISO-A.5.18'],
  'login-session':           ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'ip-restrictions':         ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-003'],
  'password-session-policy': ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'field-level-security':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'sharing-model':           ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'public-group-sharing':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'guest-user-access':       ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-CPORTAL-002'],
  'apex-sharing':            ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-CPORTAL-001'],
  'flows-without-sharing':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-CPORTAL-004'],
  'connected-apps':          ['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.8.3', 'SBS-OAUTH-001', 'SBS-OAUTH-002', 'SBS-DEP-006'],
  'remote-sites':            ['OWASP-A05', 'OWASP-A10', 'SOC2-CC6.6', 'ISO-A.8.26', 'SBS-INT-002'],
  'csp-trusted-sites':       ['OWASP-A05', 'OWASP-A10', 'SOC2-CC6.6', 'ISO-A.8.26'],
  'named-credentials':       ['OWASP-A02', 'OWASP-A10', 'SOC2-CC6.7', 'ISO-A.8.3', 'SBS-INT-003'],
  'hardcoded-credentials':   ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.8.3', 'SBS-DEP-005'],
  'custom-settings':         ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.8.3'],
  'health-check':            ['OWASP-A05', 'SOC2-CC7.1', 'ISO-A.8.8', 'SBS-SECCONF-001', 'SBS-SECCONF-002'],
  'audit-trail':             ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-002'],
  'code-security':           ['OWASP-A03', 'OWASP-A05', 'SOC2-CC7.2', 'ISO-A.8.25', 'SBS-CODE-002'],
  'api-limits':              ['OWASP-A05', 'SOC2-CC9.1', 'ISO-A.8.8', 'SBS-MON-005'],
  'scheduled-apex':          ['OWASP-A05', 'SOC2-CC7.2', 'ISO-A.8.32'],
  'standard-profiles':       ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'SBS-ACS-005'],
  'sso-enforcement':         ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-001', 'SBS-AUTH-002'],
  'mfa-enforcement':         ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-004'],
  'api-client-permission':   ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.8.3', 'SBS-ACS-006'],
  'integration-users':       ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-ACS-007', 'SBS-ACS-008', 'SBS-ACS-009'],
  'content-links':           ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.14', 'SBS-FILE-001', 'SBS-FILE-002', 'SBS-FILE-003'],
  'field-history-tracking':  ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-DATA-004'],
  'data-classification':     ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.12', 'SBS-DATA-001', 'SBS-DATA-002'],
  'deployment-identity':     ['OWASP-A05', 'OWASP-A08', 'SOC2-CC8.1', 'ISO-A.8.32', 'SBS-DEP-001', 'SBS-DEP-003'],
  'apex-logging':            ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-CODE-003', 'SBS-CODE-004'],
  'event-monitoring':        ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-001', 'SBS-INT-004'],
  'siem-integration':        ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-003', 'SBS-MON-004'],
  'apex-crud-fls':           ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'apex-rest-endpoint':      ['OWASP-A01', 'OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'visualforce-xss':         ['OWASP-A03', 'SOC2-CC6.1', 'ISO-A.8.25'],
  'certificate-expiry':      ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.8.24'],
  'installed-packages':      ['OWASP-A06', 'OWASP-A08', 'SOC2-CC9.2', 'ISO-A.8.25'],
  'trusted-ip-ranges':       ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-003'],
  'anonymous-apex-audit':    ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15'],
  'debug-log-access':        ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15'],
  'connected-app-inactivity':['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.5.18'],
  'my-domain-login-policy':  ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-001'],
  'high-assurance-session':  ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'enhanced-domains':        ['OWASP-A05', 'SOC2-CC6.1', 'ISO-A.8.26'],
  'internal-user-mfa':       ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-004'],
  'mfa-registration':        ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'mfa-method-strength':     ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'release-updates':         ['OWASP-A06', 'SOC2-CC7.1', 'ISO-A.8.8'],
  'legacy-api-version':      ['OWASP-A06', 'SOC2-CC6.6', 'ISO-A.8.8'],
  'connected-app-scope':     ['OWASP-A01', 'OWASP-A05', 'SOC2-CC6.6', 'ISO-A.8.3', 'SBS-OAUTH-002'],
  'transaction-security-policy': ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-003'],
  'failed-login-detection':  ['OWASP-A07', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-003'],
  'experience-cloud-site':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-CPORTAL-003'],
  'custom-labels-credential':['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.8.3'],
  'report-folder-access':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'escalation-perms':        ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'SBS-ACS-004'],
  'cors-allowlist':          ['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.8.26'],
  'guest-executable-apex':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-CPORTAL-001', 'SBS-CPORTAL-002'],
  'email-security':          ['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.5.14'],
  'outbound-messages':       ['OWASP-A05', 'OWASP-A10', 'SOC2-CC6.6', 'ISO-A.8.26'],
  'public-content-exposure': ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.14'],
  'privileged-access':       ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'SBS-ACS-004'],
  'separation-of-duties':    ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'SBS-ACS-004'],
  'guest-object-exposure':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-CPORTAL-002'],
  'guest-site-options':      ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.14', 'SBS-CPORTAL-003'],
  'threat-detection':        ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-001'],
};

// NZ pack crosswalk — each check belongs to one domain; the domain's NZ control ids are
// layered onto its base entry. HISO/NZISM are domain/chapter-level drafts; Privacy Act IPPs
// are statute-level. All verified:false until the verification pass.
const NZ_CROSSWALK: Array<{ controls: string[]; checks: string[] }> = [
  { controls: ['HISO-AC', 'NZISM-AC', 'PRIVACY-IPP5'],
    checks: ['users-and-admins', 'permissions', 'sharing-model', 'public-group-sharing', 'guest-user-access',
             'field-level-security', 'standard-profiles', 'api-client-permission', 'integration-users',
             'escalation-perms', 'report-folder-access', 'apex-crud-fls', 'apex-rest-endpoint',
             'guest-executable-apex', 'experience-cloud-site', 'content-links', 'apex-sharing', 'flows-without-sharing',
             'public-content-exposure', 'privileged-access', 'separation-of-duties',
             'guest-object-exposure', 'guest-site-options'] },
  { controls: ['HISO-AUTH', 'NZISM-AUTH', 'PRIVACY-IPP5'],
    checks: ['login-session', 'ip-restrictions', 'password-session-policy', 'sso-enforcement', 'mfa-enforcement',
             'trusted-ip-ranges', 'my-domain-login-policy', 'high-assurance-session', 'internal-user-mfa',
             'mfa-registration', 'mfa-method-strength', 'failed-login-detection', 'enhanced-domains'] },
  { controls: ['HISO-CRYPTO', 'NZISM-CRYPTO', 'PRIVACY-IPP5'],
    checks: ['named-credentials', 'hardcoded-credentials', 'custom-settings', 'certificate-expiry', 'custom-labels-credential'] },
  { controls: ['HISO-LOG', 'NZISM-LOG'],
    checks: ['audit-trail', 'apex-logging', 'event-monitoring', 'siem-integration', 'anonymous-apex-audit',
             'debug-log-access', 'transaction-security-policy', 'threat-detection'] },
  { controls: ['HISO-DEV', 'NZISM-SW'],
    checks: ['code-security', 'visualforce-xss', 'scheduled-apex'] },
  { controls: ['HISO-COMM', 'NZISM-NET', 'PRIVACY-IPP12'],
    checks: ['remote-sites', 'csp-trusted-sites', 'connected-apps', 'connected-app-scope', 'connected-app-inactivity', 'cors-allowlist',
             'email-security', 'outbound-messages'] },
  { controls: ['HISO-DATA', 'PRIVACY-IPP5'],
    checks: ['data-classification', 'field-history-tracking'] },
  { controls: ['HISO-GOV', 'NZISM-CONFIG'],
    checks: ['health-check', 'api-limits', 'release-updates', 'legacy-api-version', 'installed-packages', 'deployment-identity'] },
  { controls: ['PRIVACY-IPP9'],
    checks: ['inactive-users'] },
];

function buildCheckControlMap(): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const [check, ids] of Object.entries(BASE_CHECK_CONTROL_MAP)) map[check] = [...ids];
  for (const group of NZ_CROSSWALK) {
    for (const check of group.checks) {
      (map[check] ??= []).push(...group.controls);
    }
  }
  return map;
}

export const CHECK_CONTROL_MAP: Record<string, string[]> = buildCheckControlMap();
