import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface TspRecord {
  Id: string;
  Name: string;
  EventType: string;
  State: string;
}

export class TransactionSecurityPolicyCheck implements SecurityCheck {
  readonly id = 'transaction-security-policy';
  readonly name = 'Transaction Security Policies';
  readonly category = 'Threat Detection';
  readonly description =
    'Checks whether Transaction Security Policies are configured to provide automated threat detection and response';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/TransactionSecurityPolicies/home`;

    let policies: TspRecord[];
    try {
      policies = await ctx.tooling.query<TspRecord>(
        `SELECT Id, Name, EventType, State FROM TransactionSecurityPolicy WHERE State = 'Enabled'`,
      );
    } catch {
      findings.push({
        id: 'transaction-security-policy-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Transaction Security Policies could not be queried',
        detail:
          'The Tooling API TransactionSecurityPolicy query was not accessible. This may indicate the audit user lacks Tooling API access, or Transaction Security is not enabled for this org.',
        remediation:
          'Enable Transaction Security in Setup and grant Tooling API access to the audit user, then re-run.',
      });
      return { findings };
    }

    if (policies.length === 0) {
      findings.push({
        id: 'transaction-security-policy-none',
        category: this.category,
        riskLevel: 'HIGH',
        title: 'No Transaction Security Policies are enabled',
        detail:
          'Transaction Security Policies provide automated, real-time threat detection and response within Salesforce. With no policies enabled, the org has no automated defence against: credential stuffing and brute-force attacks, impossible-travel logins (e.g. login from two countries within minutes), bulk data downloads and mass API queries, concurrent session anomalies, and privilege escalation attempts. An attacker who compromises any credential can operate without triggering any automated response.',
        remediation:
          'Enable Transaction Security (Setup → Transaction Security Policies) and create policies for at minimum: (1) Login anomalies: impossible travel, concurrent sessions from different IPs; (2) Data export: block or notify on bulk Report/List View exports; (3) API anomalies: high-volume REST/SOAP queries. Recommended actions: Block + Notify for critical events; Notify for informational events.',
        affectedItems: [
          {
            label: 'Transaction Security Policies',
            url: setupUrl,
            note: 'No policies enabled: real-time threat response is completely absent',
          },
        ],
      });
      return { findings };
    }

    const eventTypes = [...new Set(policies.map((p) => p.EventType))].sort();

    findings.push({
      id: 'transaction-security-policy-present',
      category: this.category,
      riskLevel: 'LOW',
      passed: true,
      title: `${policies.length} Transaction Security Polic${policies.length === 1 ? 'y' : 'ies'} enabled`,
      detail: `Active Transaction Security Policies covering: ${eventTypes.join(', ')}. Automated threat detection and response is in place for these event types.`,
      remediation:
        'Periodically review policies to ensure coverage includes login anomalies, bulk data exports, and high-volume API usage. Verify that policy actions (Block/Notify) are appropriate for each event type.',
      affectedItems: policies.map((p) => ({
        label: p.Name,
        url: setupUrl,
        note: `EventType: ${p.EventType}`,
      })),
    });

    return { findings };
  }
}
