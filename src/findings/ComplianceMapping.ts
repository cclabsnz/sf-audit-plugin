// Maps each SecurityCheck `id` to its compliance framework references.
// Tags use the format: <Framework>-<Control> e.g. OWASP-A01, SOC2-CC6.1, ISO-A.9.2
export const COMPLIANCE_MAP: Record<string, string[]> = {
  'users-and-admins':        ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.2', 'HIPAA-164.312a', 'GDPR-Art.32'],
  'permissions':             ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.2', 'GDPR-Art.32'],
  'inactive-users':          ['OWASP-A01', 'SOC2-CC6.2', 'ISO-A.9.2', 'HIPAA-164.312a', 'GDPR-Art.5'],
  'login-session':           ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312a', 'GDPR-Art.32'],
  'ip-restrictions':         ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312a', 'GDPR-Art.32'],
  'password-session-policy': ['OWASP-A07', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312d', 'GDPR-Art.32'],
  'field-level-security':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312a', 'GDPR-Art.5'],
  'sharing-model':           ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312a', 'GDPR-Art.32'],
  'public-group-sharing':    ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.4', 'HIPAA-164.312a', 'GDPR-Art.32'],
  'guest-user-access':       ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.2', 'GDPR-Art.32'],
  'apex-sharing':            ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.4', 'GDPR-Art.32'],
  'flows-without-sharing':   ['OWASP-A01', 'SOC2-CC6.1', 'ISO-A.9.4', 'GDPR-Art.32'],
  'connected-apps':          ['OWASP-A05', 'SOC2-CC6.6', 'ISO-A.9.4', 'GDPR-Art.32'],
  'remote-sites':            ['OWASP-A05', 'SOC2-CC6.4', 'ISO-A.14.1', 'GDPR-Art.32'],
  // Pre-declared for CspTrustedSitesCheck (added in registry separately)
  'csp-trusted-sites':       ['OWASP-A05', 'SOC2-CC6.4', 'ISO-A.14.1', 'GDPR-Art.32'],
  'named-credentials':       ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.9.4', 'GDPR-Art.32'],
  'hardcoded-credentials':   ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.9.4', 'HIPAA-164.312d', 'GDPR-Art.32'],
  'custom-settings':         ['OWASP-A02', 'SOC2-CC6.7', 'ISO-A.9.4', 'GDPR-Art.32'],
  'health-check':            ['OWASP-A05', 'SOC2-CC7.1', 'ISO-A.12.6', 'GDPR-Art.32'],
  'audit-trail':             ['OWASP-A09', 'SOC2-CC7.2', 'ISO-A.12.4', 'HIPAA-164.312b', 'GDPR-Art.32'],
  'code-security':           ['OWASP-A05', 'SOC2-CC7.2', 'ISO-A.14.2', 'GDPR-Art.32'],
  'api-limits':              ['OWASP-A05', 'SOC2-CC9.1', 'ISO-A.12.6', 'GDPR-Art.32'],
  'scheduled-apex':          ['OWASP-A05', 'SOC2-CC7.2', 'ISO-A.12.1', 'GDPR-Art.32'],
};

export function getComplianceTags(checkId: string): string[] {
  return COMPLIANCE_MAP[checkId] ?? [];
}
