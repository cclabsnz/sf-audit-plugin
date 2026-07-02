import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface NetworkRec {
  Id: string;
  Name: string;
  Status: string;
}

/**
 * Advisory review of Experience Cloud CSP / Lightning Web Security posture.
 * The per-site CSP level ("Strict" vs "Relaxed") and the Lightning Web Security
 * toggle are not reliably exposed to SOQL/Tooling, so for each live site this
 * emits a targeted manual-verification item rather than a false pass. Relaxed CSP
 * or disabled LWS on a public site widens the XSS / script-injection surface that
 * unauthenticated visitors can reach.
 */
export class ExperienceCspCheck implements SecurityCheck {
  readonly id = 'experience-csp';
  readonly name = 'Experience Cloud CSP & Lightning Web Security';
  readonly category = 'Access Control';
  readonly description =
    'Advises verifying Strict CSP and Lightning Web Security on live Experience Cloud sites (not reliably API-readable), to limit XSS/script-injection exposure';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let networks: NetworkRec[];
    try {
      networks = await ctx.soql.queryAll<NetworkRec>("SELECT Id, Name, Status FROM Network WHERE Status = 'Live'");
    } catch {
      findings.push({
        id: 'experience-csp-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Experience Cloud sites could not be queried (insufficient access)',
        detail: 'The Network object was not accessible, so CSP/LWS posture could not be assessed. This may mean no Experience Cloud licence.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run. If Experience Cloud is unused, this check is not applicable.',
      });
      return { findings };
    }

    if (networks.length === 0) {
      findings.push({
        id: 'experience-csp-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No live Experience Cloud sites',
        detail: 'No live Experience Cloud sites exist, so there is no CSP/LWS surface to review.',
        remediation: 'When a site goes live, set Security to "Strict CSP" and enable Lightning Web Security.',
      });
      return { findings };
    }

    findings.push({
      id: 'experience-csp-verify',
      category: this.category,
      riskLevel: 'INFO',
      title: `Verify Strict CSP + Lightning Web Security on ${networks.length} live Experience Cloud site(s)`,
      detail:
        'The per-site Content Security Policy level and Lightning Web Security toggle are not reliably exposed to the API, so they must be confirmed manually. A "Relaxed CSP" level or disabled Lightning Web Security lets inline/third-party scripts run on pages an unauthenticated guest can reach, widening the XSS and script-injection surface.',
      remediation:
        'For each site: Setup → Digital Experiences → (site) → Administration → Security & Privacy — set the CSP level to "Strict CSP" and enable Lightning Web Security. Review any Trusted Sites/URLs added to relax CSP.',
      affectedItems: networks.slice(0, 30).map((n) => ({ label: n.Name, url: `${baseUrl}/lightning/setup/SetupNetworks/home` })),
    });

    return { findings };
  }
}
