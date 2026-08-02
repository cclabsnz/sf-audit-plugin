import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CertRecord {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
  ExpirationDate: string | null;
}

export class CertificateExpiryCheck implements SecurityCheck {
  readonly id = 'certificate-expiry';
  readonly name = 'Certificate Expiry';
  readonly category = 'Authentication';
  readonly description = 'Checks installed certificates for impending expiry (30 / 90 / 180 day thresholds)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/CertificatesAndKeys/home`;
    const now = Date.now();

    let certs: CertRecord[] = [];
    try {
      certs = await ctx.tooling.query<CertRecord>(
        `SELECT Id, MasterLabel, DeveloperName, ExpirationDate FROM Certificate`
      );
    } catch {
      findings.push({
        id: 'certificate-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Certificate inventory could not be retrieved',
        detail:
          'The Tooling API Certificate object was not accessible. This may indicate insufficient permissions or the org edition does not support certificate management via API.',
        remediation:
          'Review installed certificates manually in Setup → Security → Certificate and Key Management.',
        affectedItems: [{ label: 'Certificate and Key Management', url: setupUrl }],
      });
      return { findings };
    }

    if (certs.length === 0) {
      findings.push({
        id: 'certificate-none',
        category: this.category,
        riskLevel: 'INFO',
        title: 'No certificates found in this org',
        detail:
          'No Certificate records were found via the Tooling API. If this org uses client certificates or JWT-based integrations, verify certificates are configured correctly.',
        remediation:
          'If certificates are required for integrations or identity providers, configure them in Setup → Security → Certificate and Key Management.',
      });
      return { findings };
    }

    const critical: CertRecord[] = [];
    const soon: CertRecord[] = [];
    const medium: CertRecord[] = [];

    for (const cert of certs) {
      if (!cert.ExpirationDate) continue;
      const msUntilExpiry = new Date(cert.ExpirationDate).getTime() - now;
      const daysUntilExpiry = Math.ceil(msUntilExpiry / 86_400_000);

      if (daysUntilExpiry <= 30) {
        critical.push(cert);
      } else if (daysUntilExpiry <= 90) {
        soon.push(cert);
      } else if (daysUntilExpiry <= 180) {
        medium.push(cert);
      }
    }

    function certNote(cert: CertRecord): string {
      if (!cert.ExpirationDate) return 'no expiry date';
      const daysLeft = Math.ceil((new Date(cert.ExpirationDate).getTime() - now) / 86_400_000);
      const expiryStr = new Date(cert.ExpirationDate).toISOString().split('T')[0];
      return `${daysLeft} day(s) until expiry: expires ${expiryStr}`;
    }

    if (critical.length > 0) {
      findings.push({
        id: 'certificate-expiring-critical',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${critical.length} certificate(s) expire within 30 days`,
        detail:
          'Expired certificates break all integrations, SSO logins, and JWT-based authentication that depend on them. Certificates expiring within 30 days require immediate replacement to avoid service disruption.',
        remediation:
          'Renew or replace expiring certificates immediately. Update all integrations and connected apps that reference these certificates. Test authentication flows after replacement.',
        affectedItems: critical.map((c) => ({
          label: c.MasterLabel,
          url: setupUrl,
          note: certNote(c),
        })),
      });
    }

    if (soon.length > 0) {
      findings.push({
        id: 'certificate-expiring-soon',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${soon.length} certificate(s) expire within 90 days`,
        detail:
          'Certificates expiring within 90 days should be renewed proactively. Waiting until expiry causes integration outages and may require emergency change-management processes.',
        remediation:
          'Schedule certificate renewal within the next 30 days. Coordinate with integration owners to update dependent systems before the certificate expires.',
        affectedItems: soon.map((c) => ({
          label: c.MasterLabel,
          url: setupUrl,
          note: certNote(c),
        })),
      });
    }

    if (medium.length > 0) {
      findings.push({
        id: 'certificate-expiring-medium',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${medium.length} certificate(s) expire within 180 days`,
        detail:
          'Certificates expiring within 180 days should be tracked and scheduled for renewal. Early planning avoids emergency renewals and ensures dependent integrations are updated in time.',
        remediation:
          'Add certificate renewal to your security maintenance calendar. Identify all integrations that depend on these certificates so they can be updated when renewed.',
        affectedItems: medium.map((c) => ({
          label: c.MasterLabel,
          url: setupUrl,
          note: certNote(c),
        })),
      });
    }

    if (critical.length === 0 && soon.length === 0 && medium.length === 0) {
      findings.push({
        id: 'certificate-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${certs.length} certificate(s) are healthy (none expire within 180 days)`,
        detail:
          `All installed certificates have more than 180 days until expiry. No immediate certificate rotation is required.`,
        remediation:
          'Continue monitoring certificate expiry dates. Re-run this audit as certificates approach the 180-day threshold.',
      });
    }

    return { findings };
  }
}
