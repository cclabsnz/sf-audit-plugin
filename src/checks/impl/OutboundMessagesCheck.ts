import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface OutboundMessageRecord {
  Id: string;
  Name: string;
  EndpointUrl: string;
  IncludeSessionId: boolean;
}

export class OutboundMessagesCheck implements SecurityCheck {
  readonly id = 'outbound-messages';
  readonly name = 'Workflow Outbound Messages';
  readonly category = 'External Connectivity';
  readonly description =
    'Flags workflow outbound messages that include a Salesforce session ID or post to cleartext (http://) endpoints: session-hijack and exfiltration vectors';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/WorkflowOutboundMessaging/home`;

    let rows: OutboundMessageRecord[];
    try {
      rows = await ctx.tooling.query<OutboundMessageRecord>(
        'SELECT Id, Name, EndpointUrl, IncludeSessionId FROM WorkflowOutboundMessage',
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'outbound-messages-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Workflow outbound messages could not be read',
        detail: `The WorkflowOutboundMessage Tooling query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    if (rows.length === 0) {
      findings.push({
        id: 'outbound-messages-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No workflow outbound messages configured',
        detail: 'No outbound messages are defined, so there is no automated POST of org data to external endpoints to review.',
        remediation: 'If outbound messages are added later, use HTTPS endpoints and avoid including the session ID.',
      });
      return { findings };
    }

    const isCleartext = (url: string): boolean => /^http:\/\//i.test(url.trim());

    const sessionId = rows.filter((r) => r.IncludeSessionId);
    const cleartext = rows.filter((r) => isCleartext(r.EndpointUrl));

    if (sessionId.length > 0) {
      findings.push({
        id: 'outbound-messages-session-id',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${sessionId.length} outbound message(s) send a Salesforce session ID to an external endpoint`,
        detail:
          'Outbound messages with "Include Session ID" enabled deliver a live, API-capable Salesforce session ID to the configured endpoint with every fire. If that endpoint is attacker-controlled, compromised, or simply logs payloads, the session ID can be replayed to access the org as the integration user: a direct session-hijack and data-exfiltration path.',
        remediation:
          'Disable "Include Session ID" on every outbound message unless absolutely required. Prefer Named Credentials or OAuth for callbacks that need to authenticate to Salesforce.',
        affectedItems: sessionId.map((r) => ({
          label: r.Name,
          url: setupUrl,
          note: `${r.EndpointUrl}: disable Include Session ID`,
        })),
      });
    }

    if (cleartext.length > 0) {
      findings.push({
        id: 'outbound-messages-cleartext',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${cleartext.length} outbound message(s) post to a cleartext http:// endpoint`,
        detail:
          'Outbound messages to plain http:// endpoints transmit record data (and the session ID, if included) unencrypted over the network, where it can be intercepted in transit.',
        remediation: 'Change each endpoint to HTTPS and confirm the receiving service presents a valid certificate.',
        affectedItems: cleartext.map((r) => ({
          label: r.Name,
          url: setupUrl,
          note: `${r.EndpointUrl}: switch to HTTPS`,
        })),
      });
    }

    findings.push({
      id: 'outbound-messages-inventory',
      category: this.category,
      riskLevel: sessionId.length === 0 && cleartext.length === 0 ? 'LOW' : 'INFO',
      passed: sessionId.length === 0 && cleartext.length === 0 ? true : undefined,
      title: `${rows.length} workflow outbound message(s) configured (${sessionId.length} include session ID, ${cleartext.length} cleartext)`,
      detail:
        'Outbound messages POST record data to external endpoints automatically. Each destination should be a reviewed, currently-used HTTPS integration.',
      remediation:
        'Audit each outbound message endpoint to confirm it is still used and points to a trusted HTTPS destination. Remove unused entries.',
      affectedItems: rows.map((r) => ({
        label: r.Name,
        url: setupUrl,
        note: `${r.EndpointUrl}${r.IncludeSessionId ? ' ⚠ session ID included' : ''}`,
      })),
    });

    return { findings };
  }
}
