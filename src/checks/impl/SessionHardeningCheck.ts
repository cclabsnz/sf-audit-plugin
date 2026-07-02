import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Health Check settings that belong to the session / framing / request-forgery
// hardening domain. Matched case-insensitively against the risk `setting` name.
const SESSION_KEYWORDS = [
  'clickjack', 'frame', 'csrf', 'cross-site request', 'session', 'timeout',
  'xss', 'content sniffing', 'content-type', 'referrer', 'httponly', 'lock sessions',
  'cache', 'mixed content', 'browser', 'redirect',
];

/**
 * Re-slices the Health Check risk set (populated by HealthCheckCheck, so no extra
 * API call) to the session / clickjack / CSRF / XSS hardening domain and gives
 * targeted, per-setting remediation. HealthCheckCheck reports a flat count; this
 * check tells you *which* browser-session protections deviate from Salesforce's
 * baseline and how to fix each — the "enable secure config" surface.
 */
export class SessionHardeningCheck implements SecurityCheck {
  readonly id = 'session-hardening';
  readonly name = 'Session & Clickjack Hardening';
  readonly category = 'Session Security';
  readonly description =
    'Grades clickjack, CSRF, session-lock, and XSS-protection settings from Health Check and gives per-setting remediation';

  readonly dependsOnCache = ['healthCheckRisks'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/SessionSettings/home`;

    // Prefer authoritative SecuritySettings (Metadata API) — it reports the actual
    // values, not just Health Check deviations. Fall back to the Health Check risk
    // cache when no Metadata client is available or the shape is unexpected.
    const fromMeta = await this.evaluateFromMetadata(ctx, setupUrl);
    if (fromMeta) {
      findings.push(fromMeta);
      return { findings };
    }

    const risks = ctx.cache.healthCheckRisks;

    if (risks === undefined) {
      findings.push({
        id: 'session-hardening-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Health Check risks unavailable — session hardening not evaluated',
        detail: 'The Security Health Check risk data was not collected (Health Check check did not run or was inaccessible), so session/clickjack settings could not be graded.',
        remediation: 'Ensure the audit user can read SecurityHealthCheckRisks (View Health Check), then re-run.',
      });
      return { findings };
    }

    const matched = risks.filter((r) => {
      const s = (r.setting ?? '').toLowerCase();
      return SESSION_KEYWORDS.some((k) => s.includes(k));
    });

    if (matched.length === 0) {
      findings.push({
        id: 'session-hardening-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No session/clickjack/CSRF settings flagged by Health Check',
        detail: 'None of the browser-session hardening settings (clickjack protection, CSRF protection, session lock, XSS protection) deviate from the Salesforce baseline in Health Check.',
        remediation: 'Keep clickjack protection at the highest level, CSRF protection on for GET and POST, and "Lock sessions to the IP address from which they originated" enabled where feasible.',
      });
      return { findings };
    }

    const high = matched.filter((r) => r.riskType === 'HIGH_RISK');
    const level = high.length > 0 ? 'HIGH' : 'MEDIUM';
    findings.push({
      id: 'session-hardening-risks',
      category: this.category,
      riskLevel: level,
      title: `${matched.length} session/clickjack/CSRF setting(s) deviate from the security baseline`,
      detail:
        'These browser-session hardening settings differ from Salesforce\'s recommended values. Weak framing, CSRF, session-lock, or XSS-protection settings enable clickjacking, cross-site request forgery, session hijacking, and reflected-XSS attacks against authenticated users.',
      remediation:
        'In Setup → Session Settings (and Session Security Levels), align each flagged setting to the recommended value: highest clickjack protection for all pages, CSRF protection on GET and POST, "Lock sessions to the IP address" and "to the domain", content-sniffing and XSS protection on, and warnings on redirects to external URLs.',
      affectedItems: matched.slice(0, 30).map((r) => ({
        label: `${r.setting} = ${r.value} (${r.riskType})`,
        url: setupUrl,
      })),
    });

    return { findings };
  }

  // SecuritySettings.sessionSettings flags that should be ON (true = protected).
  private static readonly FLAGS: Array<{ key: string; label: string; sev: 'HIGH' | 'MEDIUM' }> = [
    { key: 'enableClickjackNonsetupUser', label: 'Clickjack protection (customer Visualforce pages)', sev: 'HIGH' },
    { key: 'enableClickjackNonsetupSFDC', label: 'Clickjack protection (Salesforce pages)', sev: 'HIGH' },
    { key: 'enableXssProtection', label: 'XSS protection', sev: 'HIGH' },
    { key: 'enableCSRFOnGet', label: 'CSRF protection on GET requests', sev: 'MEDIUM' },
    { key: 'enableCSRFOnPost', label: 'CSRF protection on POST requests', sev: 'MEDIUM' },
    { key: 'enableContentSniffingProtection', label: 'Content-sniffing protection', sev: 'MEDIUM' },
  ];

  /** Authoritative evaluation from SecuritySettings metadata; null → fall back to the cache path. */
  private async evaluateFromMetadata(ctx: AuditContext, setupUrl: string): Promise<Finding | null> {
    if (!ctx.metadata) return null;
    let ss: { sessionSettings?: Record<string, unknown> } | null;
    try {
      ss = await ctx.metadata.read<{ sessionSettings?: Record<string, unknown> }>('SecuritySettings', 'Security');
    } catch {
      return null;
    }
    const s = ss?.sessionSettings;
    if (!s || typeof s !== 'object') return null;

    const gaps: Array<{ label: string; sev: 'HIGH' | 'MEDIUM' }> = [];
    let sawAny = false;
    for (const f of SessionHardeningCheck.FLAGS) {
      const v = (s as Record<string, unknown>)[f.key];
      if (typeof v === 'boolean') {
        sawAny = true;
        if (!v) gaps.push({ label: f.label, sev: f.sev });
      }
    }
    if (!sawAny) return null; // unexpected shape — defer to the Health Check cache path

    if (gaps.length === 0) {
      return {
        id: 'session-hardening-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Clickjack/CSRF/XSS protections confirmed enabled',
        detail: 'SecuritySettings confirms clickjack, CSRF, XSS, and content-sniffing protections are enabled.',
        remediation: 'Also confirm "Lock sessions to the IP address from which they originated" and a short session timeout in Setup → Session Settings.',
      };
    }

    return {
      id: 'session-hardening-risks',
      category: this.category,
      riskLevel: gaps.some((g) => g.sev === 'HIGH') ? 'HIGH' : 'MEDIUM',
      title: `${gaps.length} browser-session protection(s) are disabled`,
      detail:
        'SecuritySettings reports these session/framing protections are OFF. Disabled clickjack, CSRF, XSS, or content-sniffing protection enables clickjacking, cross-site request forgery, reflected XSS, and MIME-confusion attacks against authenticated users.',
      remediation:
        'In Setup → Session Settings, enable the disabled protections: highest clickjack protection for all page types, CSRF protection on GET and POST, XSS protection, and content-sniffing protection. Also enable "Lock sessions to the IP address" where feasible.',
      affectedItems: gaps.map((g) => ({ label: `${g.label}: OFF (${g.sev})`, url: setupUrl })),
    };
  }
}
