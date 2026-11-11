import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser {
  Id: string;
}

/**
 * The PREVENTIVE guardrail that stops guest-owned records defeating a Private OWD: "Secure guest
 * user record access". With it, guests reach records only through guest user sharing rules.
 *
 * Salesforce has enforced it in every org since Winter '21. From API 50.0,
 * SharingSettings.enableSecureGuestAccess is always true and setting it has no effect, and the
 * Release Update that once carried it is no longer served. So there is no state to read: this
 * check states the platform guarantee for orgs with guest users. It once matched a Release Update
 * by its wording ("guest" plus "record access"), which could only pick up a different guest update.
 *
 * The residual risk is the symptom, not the policy: records a guest already owns, or shares a
 * guest sharing rule grants. GuestObjectExposureCheck and GuestUserAccessCheck read those directly.
 * Degrades to inconclusive if guest users cannot be read.
 */
export class GuestRecordAccessPolicyCheck implements SecurityCheck {
  readonly id = 'guest-record-access-policy';
  readonly name = 'Secure Guest User Record Access';
  readonly category = 'Access Control';
  readonly description =
    'Confirms the platform enforces "Secure guest user record access" for orgs with guest users, the guardrail that stops guest-owned records defeating a Private org-wide default';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/SecuritySharing/page`;

    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>(
        "SELECT Id FROM User WHERE UserType = 'Guest' AND IsActive = true",
      );
    } catch (err) {
      findings.push(this.inconclusive('guest-record-access-policy-inaccessible', 'Guest users could not be queried', err));
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
        remediation: 'If an Experience Cloud or Sites site is added later, review its guest user sharing rules and guest-owned records before going live.',
      });
      return { findings };
    }

    findings.push({
      id: 'guest-record-access-policy-enforced',
      category: this.category,
      riskLevel: 'LOW',
      passed: true,
      title: `"Secure guest user record access" is enforced by the platform (${guests.length} active guest user(s))`,
      detail:
        "Salesforce has enforced secure guest user record access in every org since Winter '21, and from API 50.0 the setting is always on and cannot be turned off. Guests get no access from the org-wide default, and new record access for guests comes only through guest user sharing rules. Records a guest owns, shares granted before Winter '21, and Apex or flows that run without sharing can still reach records.",
      remediation:
        'Nothing to switch on. Review the residual paths: guest-object-exposure and guest-user-access report guest-owned and guest-shared records, and guest-executable-apex reports Apex guests can run without sharing.',
      affectedItems: [{ label: 'Sharing Settings', url: setupUrl, note: 'Enforced by the platform' }],
    });
    return { findings };
  }

  private inconclusive(id: string, what: string, err: unknown): Finding {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: what,
      detail: `The audit user could not gather the data needed to evaluate guest record-access enforcement. The org returned: ${msg}`,
      remediation:
        'If the error is an access error, grant the audit user View Setup and Configuration (see PERMISSIONS.md) and re-run. Otherwise the area is unassessed, not clean.',
    };
  }
}
