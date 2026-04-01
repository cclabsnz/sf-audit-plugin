import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface DescribeResult { name: string; sharingModel: string; }

const OBJECTS_TO_CHECK = ['Account', 'Contact', 'Opportunity', 'Case', 'Lead'];

export class SharingModelCheck implements SecurityCheck {
  readonly id = 'sharing-model';
  readonly name = 'Org-Wide Defaults (OWD) Sharing Model';
  readonly category = 'Data Access Control';
  readonly description = 'Checks OWD sharing settings for Account, Contact, Opportunity, Case, and Lead';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const owdUrl = `${baseUrl}/lightning/setup/SecuritySharing/page`;

    const publicReadWriteObjects: Array<{ name: string; sharingModel: string }> = [];

    for (const objectName of OBJECTS_TO_CHECK) {
      try {
        const result = await ctx.rest.get<DescribeResult>(`/sobjects/${objectName}/describe/`);
        const { sharingModel } = result;

        if (sharingModel === 'ReadWrite' || sharingModel === 'ReadWriteTransfer') {
          publicReadWriteObjects.push({ name: objectName, sharingModel });
        }
      } catch {
        // Skip objects that fail to describe (e.g., org without certain modules)
        continue;
      }
    }

    const count = publicReadWriteObjects.length;
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

    if (count >= 3) riskLevel = 'HIGH';
    else if (count >= 1) riskLevel = 'MEDIUM';
    else riskLevel = 'LOW';

    if (count > 0) {
      findings.push({
        id: 'sharing-model-public-read-write',
        category: this.category,
        riskLevel,
        title: `${count} object(s) have Public Read/Write org-wide defaults`,
        detail: 'Org-wide defaults of Public Read/Write mean any user can read and edit all records of these objects regardless of ownership.',
        remediation: 'Set org-wide defaults to Private or Public Read Only for sensitive objects and use sharing rules to grant specific access.',
        affectedItems: publicReadWriteObjects.map((obj) => ({
          label: obj.name,
          url: owdUrl,
          note: `Current OWD: ${obj.sharingModel} — change to Private or Public Read Only`,
        })),
      });
    } else {
      findings.push({
        id: 'sharing-model-secure',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No objects have Public Read/Write org-wide defaults',
        detail: 'All checked standard objects have appropriately restrictive org-wide default sharing settings.',
        remediation: 'Continue monitoring OWD settings as new objects and customizations are introduced.',
      });
    }

    return { findings };
  }
}
