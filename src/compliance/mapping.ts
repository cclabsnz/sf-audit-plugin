// Maps each check id to the compliance control ids it relates to.
// Migrated from the former ComplianceMapping. A08/A10 are mapped precisely:
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
  'guest-record-access-policy': ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-CPORTAL-002'],
  'guest-traffic-anomaly':   ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-003'],
  'threat-detection':        ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-001'],
  'login-access-policy':     ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'SBS-ACS-004'],
  'data-export-access':      ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3'],
  'classic-sites':           ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-CPORTAL-003'],
  'auth-providers':          ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.8.3', 'SBS-AUTH-001'],
  'guest-api-access':        ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-CPORTAL-002'],
  'guest-user-visibility':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.18', 'SBS-CPORTAL-002'],
  'external-credentials':    ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.8.3', 'SBS-INT-003'],
  'login-anomaly':           ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'SBS-MON-003'],
  'session-hardening':       ['OWASP-A05', 'SOC2-CC6.1', 'ISO-A.8.26'],
  'encryption-coverage':     ['OWASP-A02', 'SOC2-CC6.1', 'ISO-A.8.24'],
  'experience-csp':          ['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.8.26'],
  'sandbox-data-masking':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.5.12'],
  // AI & Agents (v1.5). Each agent check carries its web-OWASP / SOC2 / ISO governance
  // control(s) plus the OWASP LLM Top 10 (2025) risk it maps to. LLM ids/titles are the real
  // 2025 edition (see catalogs/owaspLlm.ts). Rationale is inline per check:
  //   LLM01 Prompt Injection       — untrusted input path (public channel) or the egress a
  //                                   payload leaves through (allowlisted domain).
  //   LLM02 Sensitive Info Disclose — undetected agent-driven exfiltration (monitoring gap).
  //   LLM05 Improper Output Handling — agent output routed to an unowned/parked destination
  //                                   (the ForcedLeak exfil channel; this was "Insecure Output
  //                                   Handling / LLM02" in the 2023 list, renumbered to LLM05
  //                                   in 2025 — we map to the 2025 id honestly).
  //   LLM06 Excessive Agency        — over-broad run-as identity or write-capable action surface.
  // agent-inventory keeps its access-governance base and adds LLM06 (inventorying agent
  // identities + run-as access is the foundation of least-agency).
  'agent-inventory':         ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'LLM06'],
  'agent-user-privilege':    ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.5.18', 'LLM06'],
  'agent-action-surface':    ['OWASP-A01', 'SOC2-CC6.3', 'ISO-A.8.3', 'LLM06'],
  'agent-channel-exposure':  ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.8.3', 'LLM01'],
  'agent-monitoring-coverage':['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.8.15', 'LLM02'],
  'trusted-url-hygiene':     ['OWASP-A05', 'OWASP-A10', 'SOC2-CC6.6', 'ISO-A.8.26', 'LLM01', 'LLM05'],
};

// Domain groupings. Each check belongs to exactly one domain, and a domain's control ids are
// layered onto every base entry in it. Shared by the NZ pack and the HIPAA/GDPR crosswalk below
// so the two cannot drift apart in which checks they consider part of a domain.
const DOMAIN = {
  accessControl: ['users-and-admins', 'permissions', 'sharing-model', 'public-group-sharing', 'guest-user-access',
                  'field-level-security', 'standard-profiles', 'api-client-permission', 'integration-users',
                  'escalation-perms', 'report-folder-access', 'apex-crud-fls', 'apex-rest-endpoint',
                  'guest-executable-apex', 'experience-cloud-site', 'content-links', 'apex-sharing', 'flows-without-sharing',
                  'public-content-exposure', 'privileged-access', 'separation-of-duties',
                  'guest-object-exposure', 'guest-site-options', 'guest-record-access-policy',
                  'login-access-policy', 'data-export-access', 'classic-sites', 'guest-api-access',
                  'guest-user-visibility'],
  authentication: ['login-session', 'ip-restrictions', 'password-session-policy', 'sso-enforcement', 'mfa-enforcement',
                   'trusted-ip-ranges', 'my-domain-login-policy', 'high-assurance-session', 'internal-user-mfa',
                   'mfa-registration', 'mfa-method-strength', 'failed-login-detection', 'enhanced-domains',
                   'auth-providers'],
  crypto: ['named-credentials', 'hardcoded-credentials', 'custom-settings', 'certificate-expiry', 'custom-labels-credential', 'external-credentials', 'encryption-coverage'],
  logging: ['audit-trail', 'apex-logging', 'event-monitoring', 'siem-integration', 'anonymous-apex-audit',
            'debug-log-access', 'transaction-security-policy', 'threat-detection', 'guest-traffic-anomaly',
            'login-anomaly'],
  devSecurity: ['code-security', 'visualforce-xss', 'scheduled-apex'],
  network: ['remote-sites', 'csp-trusted-sites', 'connected-apps', 'connected-app-scope', 'connected-app-inactivity', 'cors-allowlist',
            'email-security', 'outbound-messages', 'experience-csp'],
  dataGovernance: ['data-classification', 'field-history-tracking', 'sandbox-data-masking'],
  configGovernance: ['health-check', 'api-limits', 'release-updates', 'legacy-api-version', 'installed-packages', 'deployment-identity', 'session-hardening'],
  accountLifecycle: ['inactive-users'],
  // Agentforce / GenAI. The NZ pack does not map these (HISO/NZISM predate agentic platforms and
  // have no chapter that fits); HIPAA and GDPR do, because an over-privileged agent user reading
  // PHI or personal data is squarely an access-control and security-of-processing question.
  aiAgents: ['agent-inventory', 'agent-user-privilege', 'agent-action-surface', 'agent-channel-exposure',
             'agent-monitoring-coverage', 'trusted-url-hygiene'],
} as const;

// NZ pack crosswalk — HISO/NZISM are domain/chapter-level; Privacy Act IPPs are statute-level.
const NZ_CROSSWALK: Array<{ controls: string[]; checks: readonly string[] }> = [
  { controls: ['HISO-AC', 'NZISM-AC', 'PRIVACY-IPP5'], checks: DOMAIN.accessControl },
  { controls: ['HISO-AUTH', 'NZISM-AUTH', 'PRIVACY-IPP5'], checks: DOMAIN.authentication },
  { controls: ['HISO-CRYPTO', 'NZISM-CRYPTO', 'PRIVACY-IPP5'], checks: DOMAIN.crypto },
  { controls: ['HISO-LOG', 'NZISM-LOG'], checks: DOMAIN.logging },
  { controls: ['HISO-DEV', 'NZISM-SW'], checks: DOMAIN.devSecurity },
  { controls: ['HISO-COMM', 'NZISM-NET', 'PRIVACY-IPP12'], checks: DOMAIN.network },
  { controls: ['HISO-DATA', 'PRIVACY-IPP5'], checks: DOMAIN.dataGovernance },
  { controls: ['HISO-GOV', 'NZISM-CONFIG'], checks: DOMAIN.configGovernance },
  { controls: ['PRIVACY-IPP9'], checks: DOMAIN.accountLifecycle },
];

// HIPAA / GDPR crosswalk — the domain-wide obligations. Anything narrower than a whole domain is
// mapped per check in REGULATORY_PRECISE below rather than swept across the domain, because these
// ids name a specific implementation specification or article paragraph: claiming "automatic
// logoff" against all fourteen authentication checks would be the imprecision the sourced catalog
// exists to avoid.
const REGULATORY_CROSSWALK: Array<{ controls: string[]; checks: readonly string[] }> = [
  { controls: ['HIPAA-164.312(a)(1)', 'HIPAA-164.308(a)(4)', 'GDPR-Art5(1)(f)', 'GDPR-Art25', 'GDPR-Art32(1)(b)'],
    checks: DOMAIN.accessControl },
  { controls: ['HIPAA-164.312(d)', 'GDPR-Art5(1)(f)', 'GDPR-Art32(1)(b)'],
    checks: DOMAIN.authentication },
  { controls: ['HIPAA-164.312(a)(2)(iv)', 'GDPR-Art32(1)(a)', 'GDPR-Art5(1)(f)'],
    checks: DOMAIN.crypto },
  { controls: ['HIPAA-164.312(b)', 'HIPAA-164.308(a)(1)(ii)(D)', 'GDPR-Art32(1)(b)', 'GDPR-Art33'],
    checks: DOMAIN.logging },
  { controls: ['HIPAA-164.312(c)(1)', 'GDPR-Art25', 'GDPR-Art32(1)(b)'],
    checks: DOMAIN.devSecurity },
  { controls: ['HIPAA-164.312(e)(1)', 'GDPR-Art44', 'GDPR-Art32(1)(b)'],
    checks: DOMAIN.network },
  { controls: ['HIPAA-164.308(a)(1)(ii)(A)', 'HIPAA-164.312(c)(1)', 'GDPR-Art30', 'GDPR-Art5(1)(f)'],
    checks: DOMAIN.dataGovernance },
  { controls: ['HIPAA-164.308(a)(1)(ii)(B)', 'HIPAA-164.308(a)(8)', 'GDPR-Art32(1)(d)'],
    checks: DOMAIN.configGovernance },
  { controls: ['HIPAA-164.308(a)(3)', 'GDPR-Art5(1)(f)'],
    checks: DOMAIN.accountLifecycle },
];

// Per-check HIPAA/GDPR additions, where the obligation is narrower than its domain.
const REGULATORY_PRECISE: Record<string, string[]> = {
  // Shared/service identities vs "assign a unique name and/or number for identifying and tracking user identity".
  'integration-users':          ['HIPAA-164.312(a)(2)(i)'],
  // Session inactivity timeout is the automatic-logoff specification; password rules are their own.
  'password-session-policy':    ['HIPAA-164.312(a)(2)(iii)', 'HIPAA-164.308(a)(5)(ii)(D)'],
  'session-hardening':          ['HIPAA-164.312(a)(2)(iii)'],
  // Monitoring log-in attempts and reporting discrepancies.
  'login-session':              ['HIPAA-164.308(a)(5)(ii)(C)'],
  'failed-login-detection':     ['HIPAA-164.308(a)(5)(ii)(C)'],
  'login-anomaly':              ['HIPAA-164.308(a)(5)(ii)(C)'],
  // Identifying and responding to suspected or known security incidents.
  'transaction-security-policy':['HIPAA-164.308(a)(6)'],
  'threat-detection':           ['HIPAA-164.308(a)(6)'],
  'guest-traffic-anomaly':      ['HIPAA-164.308(a)(6)'],
  // Cleartext transport of PHI/personal data — encryption in transmission.
  'remote-sites':               ['HIPAA-164.312(e)(2)(ii)'],
  'csp-trusted-sites':          ['HIPAA-164.312(e)(2)(ii)'],
  'outbound-messages':          ['HIPAA-164.312(e)(2)(ii)'],
  'email-security':             ['HIPAA-164.312(e)(2)(ii)'],
  'experience-csp':             ['HIPAA-164.312(e)(2)(ii)'],
  // Data Mask is pseudonymisation in the Art. 32(1)(a) sense; unmasked prod data in a sandbox is
  // also a by-default-accessibility failure under Art. 25.
  'sandbox-data-masking':       ['GDPR-Art32(1)(a)', 'GDPR-Art25'],
  // Agentforce / GenAI — see DOMAIN.aiAgents.
  'agent-inventory':            ['HIPAA-164.308(a)(4)', 'GDPR-Art30'],
  'agent-user-privilege':       ['HIPAA-164.312(a)(1)', 'HIPAA-164.308(a)(4)', 'GDPR-Art5(1)(f)', 'GDPR-Art32(1)(b)'],
  'agent-action-surface':       ['HIPAA-164.312(a)(1)', 'HIPAA-164.312(c)(1)', 'GDPR-Art25'],
  'agent-channel-exposure':     ['HIPAA-164.312(a)(1)', 'GDPR-Art25', 'GDPR-Art5(1)(f)'],
  'agent-monitoring-coverage':  ['HIPAA-164.312(b)', 'HIPAA-164.308(a)(1)(ii)(D)', 'GDPR-Art33'],
  'trusted-url-hygiene':        ['HIPAA-164.312(e)(1)', 'GDPR-Art44'],
};

function buildCheckControlMap(): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const [check, ids] of Object.entries(BASE_CHECK_CONTROL_MAP)) map[check] = [...ids];
  for (const group of [...NZ_CROSSWALK, ...REGULATORY_CROSSWALK]) {
    for (const check of group.checks) {
      (map[check] ??= []).push(...group.controls);
    }
  }
  for (const [check, ids] of Object.entries(REGULATORY_PRECISE)) {
    (map[check] ??= []).push(...ids);
  }
  // A control can arrive from both a crosswalk and a precise entry; a compliance matrix must not
  // render the same control twice for one check.
  for (const check of Object.keys(map)) map[check] = [...new Set(map[check])];
  return map;
}

export const CHECK_CONTROL_MAP: Record<string, string[]> = buildCheckControlMap();
