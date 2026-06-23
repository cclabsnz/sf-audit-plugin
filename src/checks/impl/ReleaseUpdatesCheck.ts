import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CriticalUpdateRecord {
  Id: string;
  Name: string;
  Description: string | null;
  AutoActivationDate: string | null;
  IsEnabled: boolean;
}

export class ReleaseUpdatesCheck implements SecurityCheck {
  readonly id = 'release-updates';
  readonly name = 'Pending Release Updates';
  readonly category = 'Platform Hygiene';
  readonly description = 'Flags Salesforce release updates (Critical Updates) that are pending activation, especially those past their auto-activation date';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ReleaseUpdates/home`;
    const today = new Date();

    let pendingUpdates: CriticalUpdateRecord[] = [];
    try {
      pendingUpdates = await ctx.tooling.query<CriticalUpdateRecord>(
        'SELECT Id, Name, Description, AutoActivationDate, IsEnabled FROM CriticalUpdate WHERE IsEnabled = false'
      );
    } catch {
      findings.push({
        id: 'release-updates-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Pending release updates check could not be completed',
        detail: 'The CriticalUpdate Tooling API object was not accessible. This can occur if the audit user lacks the "Customize Application" permission or if the org is on a restricted edition.',
        remediation: 'Review pending Release Updates manually in Setup → Release Updates.',
      });
      return { findings };
    }

    if (pendingUpdates.length === 0) {
      findings.push({
        id: 'release-updates-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All Salesforce release updates are enabled',
        detail: 'No pending release updates were found. The org is current with all platform changes Salesforce has made available.',
        remediation: 'After each Salesforce release (3× per year), review Release Updates in Setup to enable new updates promptly.',
      });
      return { findings };
    }

    const overdueUpdates: CriticalUpdateRecord[] = [];
    const upcomingUpdates: CriticalUpdateRecord[] = [];
    const deferredUpdates: CriticalUpdateRecord[] = [];

    for (const update of pendingUpdates) {
      if (!update.AutoActivationDate) {
        deferredUpdates.push(update);
        continue;
      }
      const autoDate = new Date(update.AutoActivationDate);
      const daysUntil = (autoDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24);
      if (daysUntil < 0) {
        overdueUpdates.push(update);
      } else if (daysUntil <= 90) {
        upcomingUpdates.push(update);
      } else {
        deferredUpdates.push(update);
      }
    }

    if (overdueUpdates.length > 0) {
      findings.push({
        id: 'release-updates-overdue',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${overdueUpdates.length} release update(s) are past their auto-activation date and still not enabled`,
        detail:
          'These updates were scheduled for automatic activation by Salesforce but remain disabled. Running without them may leave the org exposed to security issues or deprecated behaviors that Salesforce has already addressed. In some cases Salesforce may have already force-activated them. Verify current status in Setup.',
        remediation:
          'Enable these updates immediately in Setup → Release Updates. Test each one in a sandbox first. Check whether Salesforce has already force-activated any of these entries, in which case they may already be enforced despite showing as disabled.',
        affectedItems: overdueUpdates.map((u) => ({
          label: u.Name,
          url: setupUrl,
          note: `Auto-activation was: ${u.AutoActivationDate!.split('T')[0]}`,
        })),
      });
    }

    if (upcomingUpdates.length > 0) {
      findings.push({
        id: 'release-updates-upcoming',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${upcomingUpdates.length} release update(s) will be auto-activated by Salesforce within 90 days`,
        detail:
          'These updates are scheduled for automatic activation in the near term. Enabling them proactively allows time to identify and resolve any functional impact before Salesforce forces the change.',
        remediation:
          'Enable and test each update in a sandbox before its auto-activation date. Coordinate with development and QA teams to catch any regressions before the forced activation window.',
        affectedItems: upcomingUpdates.map((u) => ({
          label: u.Name,
          url: setupUrl,
          note: `Auto-activates: ${u.AutoActivationDate!.split('T')[0]}`,
        })),
      });
    }

    if (deferredUpdates.length > 0) {
      findings.push({
        id: 'release-updates-deferred',
        category: this.category,
        riskLevel: 'INFO',
        title: `${deferredUpdates.length} release update(s) are pending with no imminent deadline`,
        detail:
          'These updates are available but have no near-term auto-activation date. They should still be reviewed and enabled where applicable to stay ahead of eventual enforcement.',
        remediation:
          'Review each update in Setup → Release Updates. Enable updates that apply to your configuration and test in a sandbox before rolling out to production.',
        affectedItems: deferredUpdates.map((u) => ({
          label: u.Name,
          url: setupUrl,
          note: u.AutoActivationDate ? `Auto-activates: ${u.AutoActivationDate.split('T')[0]}` : 'No auto-activation date',
        })),
      });
    }

    return { findings };
  }
}
