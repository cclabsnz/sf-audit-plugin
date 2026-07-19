import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface TspRecord {
  Id: string;
  State?: string | null;
}

export class AgentMonitoringCoverageCheck implements SecurityCheck {
  readonly id = 'agent-monitoring-coverage';
  readonly name = 'Agentforce Monitoring Coverage';
  readonly category = 'AI & Agents';
  readonly description =
    'Flags orgs that run active Agentforce agents without Event Monitoring capture or Transaction Security policies to detect and respond to agent abuse.';

  // Depends on the agent inventory plus the event-log summary that EventMonitoringCheck
  // populates. TransactionSecurityPolicy is queried directly (Tooling), not cached.
  readonly dependsOnCache = ['agentInventory', 'agentAccess', 'eventLogSummary'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Gate: silent unless the agent inventory was built successfully.
    if (ctx.cache.agentAccess !== 'ok') return { findings };

    const inventory = ctx.cache.agentInventory ?? [];
    const activeAgents = inventory.filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    // Event capture signal, interpreted the same way SiemIntegrationCheck reads the
    // EventLogSummary: capture exists only when the log is accessible AND has files.
    // A blind log (not-enabled / no-permission) counts as "no capture" — there is no
    // monitoring the agent's activity can be seen through.
    const els = ctx.cache.eventLogSummary;
    const hasEventCapture = !!els && els.accessible !== false && (els.totalFiles ?? 0) > 0;

    // Transaction Security policies (real-time threat response). Defensive: a missing
    // object / access failure is treated as "no policy" rather than throwing — the
    // absence of detectable policy is what matters for this coverage check.
    const hasTransactionSecurity = await this.hasEnabledTransactionSecurityPolicy(ctx);

    const agentList = activeAgents
      .map((a) => `${a.label} (${a.developerName})`)
      .slice(0, 20)
      .join(', ');

    // High: agents run, nothing captures their activity, and no automated response
    // exists. Point at the events pull command.
    if (!hasEventCapture && !hasTransactionSecurity) {
      findings.push({
        id: 'agent-monitoring-coverage-none',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${activeAgents.length} active agent(s) run with no Event Monitoring capture and no Transaction Security policy`,
        detail:
          `This org has ${activeAgents.length} active Agentforce agent(s) (${agentList}) but ` +
          `Event Monitoring is not capturing any log files${els && els.accessible === false ? ' (the event log was not accessible to this audit)' : ''} ` +
          `and no Transaction Security policy is enabled. Agent activity — including prompt injection, mass reads by the run-as user, ` +
          `and data exfiltration — would leave no auditable trail and trigger no automated response. This is the monitoring gap in the ForcedLeak pattern.`,
        remediation:
          'Enable Event Monitoring (Setup → Event Monitoring Settings) and pull agent-relevant logs with `sf audit events pull` on a schedule, forwarding to a SIEM. Add Transaction Security policies for login and data-export anomalies so agent misuse triggers a real-time response.',
        affectedItems: [
          {
            label: 'Event Monitoring',
            url: `${baseUrl}/lightning/setup/EventLogFile/home`,
            note: 'No event log files captured — run `sf audit events pull`',
          },
          {
            label: 'Transaction Security Policies',
            url: `${baseUrl}/lightning/setup/TransactionSecurityPolicies/home`,
            note: 'No enabled policy — no automated response to agent abuse',
          },
        ],
      });
      return { findings };
    }

    // Low (partial): event logs exist but there is no Transaction Security policy — the
    // activity is recorded but nothing responds in real time.
    if (hasEventCapture && !hasTransactionSecurity) {
      findings.push({
        id: 'agent-monitoring-coverage-partial',
        category: this.category,
        riskLevel: 'LOW',
        title: `Agent activity is logged but no Transaction Security policy provides real-time response`,
        detail:
          `Event Monitoring is capturing log files, so ${activeAgents.length} active agent(s) leave an auditable trail. ` +
          `However, no Transaction Security policy is enabled, so anomalies in agent-driven activity (bulk reads, off-hours access, ` +
          `data export) are recorded after the fact but not blocked or alerted on in real time.`,
        remediation:
          'Add Transaction Security policies (Setup → Transaction Security Policies) for login anomalies and bulk data export so agent misuse is caught in real time, not only in retrospective log review.',
        affectedItems: [
          {
            label: 'Transaction Security Policies',
            url: `${baseUrl}/lightning/setup/TransactionSecurityPolicies/home`,
            note: 'No enabled policy — add real-time response for agent activity',
          },
        ],
      });
      return { findings };
    }

    // Otherwise monitoring is adequate (capture present, or capture + policy). Silent.
    return { findings };
  }

  private async hasEnabledTransactionSecurityPolicy(ctx: AuditContext): Promise<boolean> {
    try {
      const policies = await ctx.tooling.query<TspRecord>(
        `SELECT Id, State FROM TransactionSecurityPolicy WHERE State = 'Enabled'`,
      );
      return policies.length > 0;
    } catch {
      // Object missing or inaccessible: no detectable policy.
      return false;
    }
  }
}
