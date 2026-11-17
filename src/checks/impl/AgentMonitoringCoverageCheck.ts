import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

type Known = 'yes' | 'no' | 'unknown';

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

    // Event capture: 'yes' when the log is readable and has files; 'no' only when it is readable and
    // empty. Any read failure is 'unknown', including the 'not-enabled' class: sf-core assigns it to
    // INVALID_TYPE, which Salesforce also returns when the audit user cannot see EventLogFile, and to
    // MALFORMED_QUERY, which says nothing about the org.
    const els = ctx.cache.eventLogSummary;
    const capture: Known =
      !els ? 'unknown'
      : els.accessible !== false ? ((els.totalFiles ?? 0) > 0 ? 'yes' : 'no')
      : 'unknown';

    // Transaction Security policies (real-time threat response).
    const policy = await this.transactionSecurityPolicyState(ctx);

    // Silent when coverage is adequate on what could be read: capture plus a policy, or a policy
    // alone (the same as before this check could tell unreadable from empty).
    if (policy === 'yes') return { findings };

    const agentList = activeAgents
      .map((a) => `${a.label} (${a.developerName})`)
      .slice(0, 20)
      .join(', ');

    // High: agents run, nothing captures their activity, and no automated response
    // exists. Point at the events pull command.
    if (capture === 'no' && policy === 'no') {
      findings.push({
        id: 'agent-monitoring-coverage-none',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${activeAgents.length} active agent(s) run with no Event Monitoring capture and no Transaction Security policy`,
        detail:
          `This org has ${activeAgents.length} active Agentforce agent(s) (${agentList}) but ` +
          `the event log is readable and holds no log files ` +
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
    if (capture === 'yes' && policy === 'no') {
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

    // Something that would decide the answer could not be read: the event log (no permission, or
    // an unclassified failure) or the Transaction Security policies. Report what is unknown
    // instead of treating it as no monitoring.
    const unknownParts = [
      capture === 'unknown' &&
        (els?.accessError === 'no-permission'
          ? 'the event log (the audit user lacks View Event Log Files)'
          : 'the event log'),
      policy === 'unknown' && 'the Transaction Security policies',
    ].filter((p): p is string => typeof p === 'string');
    findings.push({
      id: 'agent-monitoring-coverage-unreadable',
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `Monitoring coverage for ${activeAgents.length} active agent(s) could not be confirmed`,
      detail:
        `This org has ${activeAgents.length} active Agentforce agent(s) (${agentList}), but this audit could not read ` +
        `${unknownParts.join(' or ')}, so it cannot tell whether their activity is captured or responded to.` +
        (capture === 'yes' ? ' Event Monitoring is capturing log files.' : '') +
        (capture === 'no' ? ' Event Monitoring is not capturing any log files.' : ''),
      remediation:
        'Grant the audit user View Event Log Files and read access to Transaction Security policies (see PERMISSIONS.md), then re-run the audit.',
      affectedItems: [
        { label: 'Event Monitoring', url: `${baseUrl}/lightning/setup/EventLogFile/home` },
        { label: 'Transaction Security Policies', url: `${baseUrl}/lightning/setup/TransactionSecurityPolicies/home` },
      ],
    });
    return { findings };
  }

  private async transactionSecurityPolicyState(ctx: AuditContext): Promise<Known> {
    try {
      const policies = await ctx.tooling.query<TspRecord>(
        `SELECT Id, State FROM TransactionSecurityPolicy WHERE State = 'Enabled'`,
      );
      return policies.length > 0 ? 'yes' : 'no';
    } catch {
      // INVALID_TYPE also means the audit user cannot see the object, so any failure is unknown.
      return 'unknown';
    }
  }
}
