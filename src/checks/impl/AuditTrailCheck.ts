import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AuditTrailRecord {
  CreatedDate: string;
  Action: string;
  Display: string;
  Section: string;
  CreatedBy: { Username: string };
}

export class AuditTrailCheck implements SecurityCheck {
  readonly id = 'audit-trail';
  readonly name = 'Audit Trail';
  readonly category = 'Security Controls';
  readonly description = 'Reviews setup audit trail for permission changes and Login-As events';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const auditTrailUrl = `${baseUrl}/lightning/setup/AuditTrail/page`;

    // Query audit trail for the last 7 days
    const auditRecords = await ctx.soql.queryAll<AuditTrailRecord>(
      `SELECT CreatedDate, CreatedBy.Username, Action, Display, Section
       FROM SetupAuditTrail
       WHERE CreatedDate > LAST_N_DAYS:7
       ORDER BY CreatedDate DESC
       LIMIT 200`
    );

    // Sensitive sections to monitor
    const sensitiveSections = [
      'Permission Sets',
      'Profiles',
      'Manage Users',
      'Security Controls',
      'Password Policies',
    ];

    // Filter for permission/security changes
    const securityChanges = auditRecords.filter((r) =>
      sensitiveSections.includes(r.Section)
    );

    const securityChangeCount = securityChanges.length;
    const securityRiskLevel =
      securityChangeCount > 20
        ? 'HIGH'
        : securityChangeCount > 10
          ? 'MEDIUM'
          : 'LOW';

    findings.push({
      id: 'permission-security-changes',
      category: this.category,
      riskLevel: securityRiskLevel,
      title: `${securityChangeCount} permission or security configuration change(s) in the last 7 days`,
      detail:
        'Frequent permission and security changes can indicate privilege escalation activity or risky configuration drift.',
      remediation:
        'Review each change in Setup → Audit Trail. Investigate unexpected changes, especially outside change-management windows.',
      affectedItems: securityChanges.slice(0, 10).map((r) => ({
        label: `${r.CreatedBy.Username}: ${r.Display}`,
        url: auditTrailUrl,
        note: new Date(r.CreatedDate).toISOString().split('T')[0],
      })),
    });

    // Query for Login-As events
    const loginAsRecords = await ctx.soql.queryAll<AuditTrailRecord>(
      `SELECT CreatedDate, CreatedBy.Username, Display
       FROM SetupAuditTrail
       WHERE CreatedDate > LAST_N_DAYS:7 AND Action LIKE '%loginAs%'
       ORDER BY CreatedDate DESC
       LIMIT 20`
    );

    if (loginAsRecords.length > 0) {
      findings.push({
        id: 'login-as-events',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${loginAsRecords.length} "Login As" event(s) recorded in the last 7 days`,
        detail:
          'Administrators logging in as other users can access their data and perform actions on their behalf.',
        remediation:
          'Review Login-As usage. Ensure it is used only for legitimate support purposes and is logged and approved.',
        affectedItems: loginAsRecords.slice(0, 10).map((r) => ({
          label: `${r.CreatedBy.Username}: ${r.Display}`,
          url: auditTrailUrl,
          note: new Date(r.CreatedDate).toISOString().split('T')[0],
        })),
      });
    }

    return { findings };
  }
}
