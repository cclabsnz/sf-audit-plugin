import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser {
  Id: string;
}
interface CriticalUpdateRecord {
  Id: string;
  Name: string;
  Description: string | null;
  IsEnabled: boolean;
}

/**
 * Verifies the PREVENTIVE guardrail that stops the guest-ownership-defeats-OWD
 * exfiltration vector: "Secure guest user record access".
 *
 * This is the policy complement to GuestObjectExposureCheck (which detects the
 * SYMPTOM — guest-owned records readable under a Private OWD). Once "Secure guest
 * user record access" is enforced, guests can no longer be granted record access
 * except via explicit guest user sharing rules, and — paired with "Assign new
 * records created by guest users to the default owner" — guests stop OWNING the
 * records they submit, which is what otherwise nullifies a Private OWD for
 * guest-submitted records (an owner can always read its own records).
 *
 * The enforcement ships as a Salesforce Release Update ("Secure guest user record
 * access", api-visible as a CriticalUpdate). This check reads that update's
 * activation state via the Tooling API and grades:
 *   - update present & IsEnabled = false  => HIGH: guardrail available, NOT activated.
 *   - update present & IsEnabled = true    => pass: guardrail enforced.
 *   - update absent (older orgs where it was auto-activated long ago, or not
 *     surfaced)                            => LOW advisory: confirm the Sharing
 *     Settings checkboxes manually, since the API no longer exposes the toggle.
 * Degrades to inconclusive if guest users or the Tooling API cannot be read.
 */
export class GuestRecordAccessPolicyCheck implements SecurityCheck {
  readonly id = 'guest-record-access-policy';
  readonly name = 'Secure Guest User Record Access';
  readonly category = 'Access Control';
  readonly description =
    'Verifies the "Secure guest user record access" enforcement is activated, the guardrail that stops guest-owned records defeating a Private org-wide default';

  // Matches the release update / sharing setting regardless of the exact label
  // Salesforce uses across versions: the name/description mentions guests AND
  // record access.
  private matchesSecureGuestAccess(u: CriticalUpdateRecord): boolean {
    const hay = `${u.Name} ${u.Description ?? ''}`.toLowerCase();
    const guest = hay.includes('guest');
    const record = hay.includes('record access') || hay.includes('record-level') || hay.includes("access to records") || hay.includes('securely access');
    return guest && record;
  }

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/SecuritySharing/page`;

    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>(
        "SELECT Id FROM User WHERE UserType = 'Guest' AND IsActive = true",
      );
    } catch {
      findings.push(this.inconclusive('guest-record-access-policy-inaccessible', 'Guest users could not be queried'));
      return { findings };
    }

    if (guests.length === 0) {
      findings.push({
        id: 'guest-record-access-policy-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users',
        detail: 'There are no active guest users, so guest record-access enforcement has no attack surface to protect.',
        remediation: 'If an Experience Cloud or Sites site is added later, ensure "Secure guest user record access" is enforced before going live.',
      });
      return { findings };
    }

    let updates: CriticalUpdateRecord[];
    try {
      updates = await ctx.tooling.query<CriticalUpdateRecord>(
        'SELECT Id, Name, Description, IsEnabled FROM CriticalUpdate',
      );
    } catch {
      findings.push(this.inconclusive('guest-record-access-policy-tooling-inaccessible', 'Release updates could not be queried'));
      return { findings };
    }

    const match = updates.find((u) => this.matchesSecureGuestAccess(u));

    if (match && !match.IsEnabled) {
      findings.push({
        id: 'guest-record-access-policy-not-enforced',
        category: this.category,
        riskLevel: 'HIGH',
        title: `"Secure guest user record access" is available but NOT activated (${guests.length} active guest user(s))`,
        detail:
          'The "Secure guest user record access" Release Update is present but not enabled. Until it is activated, guest users can be granted record access through legacy sharing mechanisms and can own the records they submit via public forms. Because an owner can always read its own records, a Private org-wide default does not protect guest-owned records — this is the exact vector that turns a public submission form into an unauthenticated bulk-read surface.',
        remediation:
          'Activate "Secure guest user record access" in Setup → Release Updates, and enable "Assign new records created by guest users to the default owner" in Setup → Sharing Settings. Reparent existing guest-owned records to an internal default/integration owner. After enforcement, grant guest read access only through explicit, minimal guest user sharing rules.',
        affectedItems: [{ label: match.Name, url: `${ctx.orgInfo.instanceUrl}/lightning/setup/ReleaseUpdates/home`, note: 'Release Update present, IsEnabled = false' }],
      });
      return { findings };
    }

    if (match && match.IsEnabled) {
      findings.push({
        id: 'guest-record-access-policy-enforced',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: '"Secure guest user record access" is enforced',
        detail:
          'The "Secure guest user record access" Release Update is enabled, so guests cannot be granted record access except through explicit guest user sharing rules. Verify "Assign new records created by guest users to the default owner" is also enabled so guests do not own the records they submit.',
        remediation:
          'Confirm "Assign new records created by guest users to the default owner" is enabled in Setup → Sharing Settings, and periodically review guest user sharing rules for least privilege.',
        affectedItems: [{ label: match.Name, url: setupUrl, note: 'Release Update enabled' }],
      });
      return { findings };
    }

    // No matching update surfaced — typical of orgs where it was auto-activated in
    // an earlier release and no longer appears in CriticalUpdate. We got data, so
    // this is advisory (LOW), not inconclusive: point the operator at the manual toggles.
    findings.push({
      id: 'guest-record-access-policy-verify-manually',
      category: this.category,
      riskLevel: 'LOW',
      title: `Confirm guest record-access guardrails manually (${guests.length} active guest user(s))`,
      detail:
        'The "Secure guest user record access" Release Update is no longer exposed via the API (usually because it was auto-activated in an earlier Salesforce release). Enforcement is therefore assumed but not API-verifiable. The two settings that jointly close the guest-ownership-defeats-OWD vector cannot be read programmatically.',
      remediation:
        'In Setup → Sharing Settings, confirm "Secure guest user record access" is on and "Assign new records created by guest users to the default owner" is enabled. Then confirm no guest user OWNS records (see the guest-object-exposure finding) and that guest access is granted only via minimal guest user sharing rules.',
      affectedItems: [{ label: 'Sharing Settings', url: setupUrl, note: 'Manual verification required' }],
    });
    return { findings };
  }

  private inconclusive(id: string, what: string): Finding {
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather the data needed to evaluate guest record-access enforcement.',
      remediation: 'Grant the audit user View Setup and Configuration plus Tooling API access, then re-run.',
    };
  }
}
