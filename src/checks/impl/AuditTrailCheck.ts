import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { hasField } from '../support/schema.js';

interface AuditTrailRecord {
  CreatedDate: string;
  Action: string;
  Display: string;
  Section: string;
  CreatedBy: { Username: string };
}

interface EventLogDeleteRecord {
  Assignee: { Id: string; Username: string; Profile?: { Name: string } };
  PermissionSet: { Name: string; IsOwnedByProfile?: boolean };
}

export class AuditTrailCheck implements SecurityCheck {
  readonly id = 'audit-trail';
  readonly name = 'Audit Trail';
  readonly category = 'Security Controls';
  readonly description = 'Reviews setup audit trail for permission changes and Login-As events';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const auditTrailUrl = `${baseUrl}/lightning/setup/AuditTrail/home`;

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
      // Zero sensitive-section changes is a pass, not a LOW finding. scoring.ts excludes only
      // passed and inconclusive findings from the penalty numerator, so leaving this unmarked
      // charged a clean seven days against the org's health score.
      passed: securityChangeCount === 0,
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

    // SBS-MON-002: flag users who can delete Event Monitoring data (erasing the audit trail).
    // PermissionsManageEventLogFiles grants the "Delete Event Monitoring Data" capability.
    try {
      // The permission field exists only in orgs licensed for Event Monitoring. Describe first:
      // filtering on an absent field is rejected outright. Absence is reported as unassessed,
      // not as a pass: this audit has not confirmed the delete capability has no other API name.
      if (!(await hasField(ctx, 'PermissionSet', 'PermissionsManageEventLogFiles'))) {
        findings.push({
          id: 'event-log-delete-permission-not-available',
          category: this.category,
          riskLevel: 'INFO',
          inconclusive: true,
          notAssessed: true,
          title: 'Who can delete Event Monitoring data could not be read: the permission is not in this org',
          detail:
            'This org has no PermissionSet.PermissionsManageEventLogFiles field, which is usual when Event Monitoring is not licensed. Who can delete event monitoring data is therefore unestablished from permissions, and SBS-MON-002 is unevaluated rather than satisfied.',
          remediation:
            'If the org licenses Event Monitoring, review who holds "Manage Event Log Files" or "Delete Event Monitoring Data" in Setup → Permission Sets.',
        });
        return { findings };
      }

      const eventLogDeleteResult = await ctx.soql.query<EventLogDeleteRecord>(
        `SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name,
                PermissionSet.Name, PermissionSet.IsOwnedByProfile
         FROM PermissionSetAssignment
         WHERE PermissionSet.PermissionsManageEventLogFiles = true
           AND Assignee.IsActive = true
           AND AssigneeId NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`
      );

      const eventLogDeleteUsers = eventLogDeleteResult.records;
      if (eventLogDeleteUsers.length > 0) {
        findings.push({
          id: 'event-log-delete-permission',
          category: this.category,
          riskLevel: 'HIGH',
          title: `${eventLogDeleteUsers.length} active user(s) can delete Event Monitoring data (Manage Event Log Files)`,
          detail:
            'SBS-MON-002 requires event logs to be protected from tampering and unauthorised deletion. Users with "Manage Event Log Files" can delete EventLogFile records, permanently destroying audit evidence.',
          remediation:
            'Remove the "Manage Event Log Files" permission from all users who do not have a specific, documented administrative need. Consider exporting logs to an immutable external SIEM before any deletion is possible.',
          affectedItems: eventLogDeleteUsers.map((r) => ({
            label: r.Assignee.Username,
            url: `${baseUrl}/${r.Assignee.Id}`,
            note: `via: ${r.PermissionSet.IsOwnedByProfile ? r.Assignee.Profile?.Name ?? 'Profile' : r.PermissionSet.Name}`,
          })),
        });
      }
    } catch (err) {
      // Skipping silently was wrong: with no finding emitted, a reader cannot tell "nobody can
      // delete event logs" from "we were unable to find out", and only the first of those is a
      // pass. Declared inconclusive so it is scored as INFO, carries no penalty, and is still shown.
      findings.push({
        id: 'event-log-delete-permission-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Manage Event Log Files assignments could not be queried',
        detail:
          `Who holds "Manage Event Log Files" could not be read, so who can delete event monitoring data is unestablished. SBS-MON-002 is unevaluated rather than satisfied. The org said: ${err instanceof Error ? err.message : String(err)}`,
        remediation:
          'Check the error above. If it is an access error, confirm the audit user can read PermissionSetAssignment (View Setup and Configuration), then re-run.',
      });
    }

    return { findings };
  }
}
