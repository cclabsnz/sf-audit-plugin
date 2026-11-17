import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Common PII-bearing fields to probe for populated, real-looking data. A count
// query is cheap and non-invasive (no values are read).
const PII_PROBES: Array<{ object: string; where: string }> = [
  { object: 'Contact', where: 'Email != null' },
  { object: 'Lead', where: 'Email != null' },
  { object: 'Contact', where: 'Phone != null' },
];

/**
 * Advisory for sandboxes: production data copied into a sandbox and left unmasked
 * spreads real PII/PHI into a lower-trust environment with weaker controls and
 * broader developer access. This check runs only in sandboxes and counts populated
 * email and phone fields. Data Mask replaces values with random characters or library
 * values rather than emptying them, so a masked sandbox also has populated fields: the
 * count shows the sandbox holds contact data, not that it is unmasked. Hence INFO.
 * https://trailhead.salesforce.com/content/learn/modules/salesforce-data-mask/get-to-know-salesforce-data-mask
 */
export class SandboxDataMaskingCheck implements SecurityCheck {
  readonly id = 'sandbox-data-masking';
  readonly name = 'Sandbox Data Masking';
  readonly category = 'Data Security';
  readonly description =
    'In sandboxes, notes populated contact email and phone fields and advises confirming that Data Mask or another masking tool has run';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    if (!ctx.orgInfo.isSandbox) {
      findings.push({
        id: 'sandbox-data-masking-na',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Not a sandbox — data masking not applicable',
        detail: 'This org is a production org, so sandbox data-masking does not apply here.',
        remediation: 'Apply Data Mask to sandboxes seeded from this production org so PII/PHI is not copied in the clear.',
      });
      return { findings };
    }

    let probed = 0;
    let populated = 0;
    for (const p of PII_PROBES) {
      try {
        const r = await ctx.soql.query<Record<string, never>>(`SELECT COUNT() FROM ${p.object} WHERE ${p.where}`);
        probed++;
        if (r.totalSize > 0) populated++;
      } catch {
        // object not present / not accessible — skip this probe
      }
    }

    if (probed === 0) {
      findings.push({
        id: 'sandbox-data-masking-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Could not probe for PII data in this sandbox',
        detail: 'None of the PII probe objects were queryable, so the presence of unmasked production data could not be assessed.',
        remediation: 'Confirm Data Mask has been run on this sandbox (Setup → Data Mask), independent of this check.',
      });
      return { findings };
    }

    if (populated > 0) {
      findings.push({
        id: 'sandbox-data-masking-pii-present',
        category: this.category,
        // Inconclusive: masked and real values look the same to these probes, so the finding
        // must not feed the sandbox-pii-exposure chain as if the data were unmasked.
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Sandbox holds contact email or phone data: confirm it was masked',
        detail:
          'This is a sandbox and Contact or Lead email or phone fields are populated. That is what a production copy looks like, but a masked sandbox looks the same, because Data Mask replaces values rather than removing them. The check cannot tell masked data from real data. If this sandbox was refreshed from production and not masked, real personal data sits in an environment with broader developer and admin access.',
        remediation:
          'Run Salesforce Data Mask on this sandbox (Setup → Data Mask) after each refresh, masking PII/PHI fields. Restrict sandbox access and treat sandbox data with the same controls as production until masking is confirmed.',
        affectedItems: [{ label: 'Data Mask', url: `${baseUrl}/lightning/setup/DataMask/home` }],
      });
    } else {
      findings.push({
        id: 'sandbox-data-masking-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Sandbox shows no populated PII in the probed fields',
        detail: `Probed ${probed} PII field(s); none were populated, consistent with a masked or data-free sandbox.`,
        remediation: 'Continue running Data Mask after each sandbox refresh.',
      });
    }

    return { findings };
  }
}
