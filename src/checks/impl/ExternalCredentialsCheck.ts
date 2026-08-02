import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ExternalCredentialRec {
  Id: string;
  DeveloperName: string;
  AuthenticationProtocol: string | null;
}

// Authentication protocols that mean the callout carries no server-verified
// credential — either fully anonymous, or a static/custom secret that is easy to
// leak or replay.
const WEAK_PROTOCOLS = new Set(['NoAuthentication', 'Custom']);

/**
 * Reviews External Credentials (the modern auth half of Named Credentials) for
 * weak authentication. Complements `named-credentials` (which inventories the
 * endpoints) by grading HOW the org authenticates to them: a credential with no
 * authentication, or a hand-rolled custom scheme, is a soft target for spoofing
 * the remote system or leaking a static secret.
 */
export class ExternalCredentialsCheck implements SecurityCheck {
  readonly id = 'external-credentials';
  readonly name = 'External Credential Authentication';
  readonly category = 'External Connectivity';
  readonly description =
    'Grades External Credential authentication protocols, flagging callouts that use no authentication or a custom (non-standard) scheme';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let creds: ExternalCredentialRec[];
    try {
      creds = await ctx.soql.queryAll<ExternalCredentialRec>('SELECT Id, DeveloperName, AuthenticationProtocol FROM ExternalCredential');
    } catch {
      findings.push({
        id: 'external-credentials-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'External Credentials could not be queried (insufficient access or unsupported)',
        detail: 'The ExternalCredential object was not accessible. This can mean the org has not migrated to External Credentials, or the audit user lacks access.',
        remediation: 'Grant the audit user View Setup and Configuration and re-run. Also review Setup → Named Credentials → External Credentials manually.',
      });
      return { findings };
    }

    if (creds.length === 0) {
      findings.push({
        id: 'external-credentials-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No External Credentials configured',
        detail: 'No ExternalCredential records exist, so there is no external-credential authentication surface to grade.',
        remediation: 'When adding External Credentials, prefer OAuth/JWT or AWS SigV4 over custom or no-authentication schemes.',
      });
      return { findings };
    }

    const weak = creds.filter((c) => WEAK_PROTOCOLS.has(c.AuthenticationProtocol ?? ''));
    if (weak.length > 0) {
      findings.push({
        id: 'external-credentials-weak-auth',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${weak.length} External Credential(s) use no or custom authentication`,
        detail:
          'These External Credentials authenticate with "No Authentication" or a "Custom" scheme. No-auth callouts can be spoofed or redirected without detection, and custom schemes typically embed a static secret that is easy to leak or replay. Standard protocols (OAuth, JWT, AWS SigV4) provide server-verified, rotatable credentials.',
        remediation:
          'Move these callouts to a standard authentication protocol (OAuth 2.0, JWT bearer, or AWS SigV4) with a rotatable secret, and confirm the paired Named Credential targets an HTTPS endpoint.',
        affectedItems: weak.map((c) => ({ label: `${c.DeveloperName} (${c.AuthenticationProtocol})`, url: `${baseUrl}/lightning/setup/NamedCredential/home` })),
      });
    } else {
      findings.push({
        id: 'external-credentials-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${creds.length} External Credential(s); all use standard authentication`,
        detail: 'No External Credential uses "No Authentication" or a custom scheme.',
        remediation: 'Continue to prefer OAuth/JWT/SigV4 and rotate secrets on a schedule.',
      });
    }

    return { findings };
  }
}
