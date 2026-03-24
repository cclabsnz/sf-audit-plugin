import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CustomObjectRecord {
  Id: string;
  DeveloperName: string;
  Description: string | null;
}

const SENSITIVE_KEYWORDS = [
  'password',
  'secret',
  'token',
  'key',
  'credential',
  'api_key',
  'apikey',
];

export class CustomSettingsCheck implements SecurityCheck {
  readonly id = 'custom-settings';
  readonly name = 'Custom Settings and Credentials';
  readonly category = 'Code Security';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    const customObjects = await ctx.tooling.query<CustomObjectRecord>(`
      SELECT Id, DeveloperName, Description FROM CustomObject 
      WHERE DeveloperName LIKE '%Setting%' 
        OR DeveloperName LIKE '%Config%' 
        OR DeveloperName LIKE '%Credential%'
    `);

    // Filter for matches with sensitive keywords
    const matches = customObjects.filter((obj: CustomObjectRecord) => {
      const devName = (obj.DeveloperName || '').toLowerCase();
      const desc = (obj.Description || '').toLowerCase();
      const combined = `${devName} ${desc}`;
      return SENSITIVE_KEYWORDS.some((keyword) => combined.includes(keyword));
    });

    if (matches.length > 0) {
      const affectedItems = matches.map((obj: CustomObjectRecord) => obj.DeveloperName);

      findings.push({
        id: 'custom-settings-credentials',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${matches.length} custom object(s) may store sensitive credentials`,
        detail: 'Custom objects named with credential-related terms may be storing API keys, passwords, or other secrets in plaintext Salesforce records.',
        remediation: 'Replace credential storage in custom objects with Named Credentials or a dedicated secrets management solution.',
        affectedItems,
      });
    } else {
      findings.push({
        id: 'custom-settings-clean',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No obviously credential-related custom objects detected',
        detail: 'No custom objects with credential-related naming patterns were found.',
        remediation: 'Continue to avoid storing secrets in custom objects or custom settings. Use Named Credentials for external authentication.',
      });
    }

    return { findings };
  }
}
