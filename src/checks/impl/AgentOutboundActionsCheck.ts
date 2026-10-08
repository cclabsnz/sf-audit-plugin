import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FunctionRow {
  Id: string;
  DeveloperName: string;
  MasterLabel?: string | null;
  Source?: string | null;
  InvocationTargetType?: string | null;
  InvocationTarget?: string | null;
  IsConfirmationRequired?: boolean | null;
}
interface PluginActionRow { PluginId: string; Function: string | null }

// Invocation types that hand data to something outside the org.
const EXTERNAL_TYPES = new Set(['slack', 'externalservice', 'externalconnector', 'mcptool', 'platformmcptool']);
// Standard invocable actions that send email (Flow's core "Send Email" and email alerts).
const EMAIL_TARGETS = new Set(['emailsimple', 'emailalert']);
// Standard Slack actions that post a message somewhere. Names verified from the
// GenAiPluginFunctionDef.Function picklist (v67.0).
const SLACK_SEND = /(^|__)(ReplyInThread|SendMessageAsAgent|SendMessageToSlackChannel|SendSlackDirectMessage)(_|$)/i;
// "SendClaimEmail", "SendVisitSummaryEmail": a name that sends rather than drafts an email.
const SEND_EMAIL_NAME = /(^|__|_)Send\w*Email/i;

type Kind = 'Slack message' | 'email' | 'external service';

function outboundKind(fn: Pick<FunctionRow, 'DeveloperName' | 'Source' | 'InvocationTargetType' | 'InvocationTarget'>): Kind | null {
  const type = (fn.InvocationTargetType ?? '').toLowerCase();
  const target = (fn.InvocationTarget ?? '').toLowerCase();
  const names = [fn.Source, fn.DeveloperName].filter((n): n is string => !!n);
  if (type === 'slack' || names.some((n) => SLACK_SEND.test(n))) return 'Slack message';
  if (EMAIL_TARGETS.has(target) || names.some((n) => SEND_EMAIL_NAME.test(n))) return 'email';
  if (EXTERNAL_TYPES.has(type)) return 'external service';
  return null;
}

export class AgentOutboundActionsCheck implements SecurityCheck {
  readonly id = 'agent-outbound-actions';
  readonly name = 'Agent Outbound Actions';
  readonly category = 'AI & Agents';
  readonly description =
    'Flags agent actions that send data out of the org (Slack messages, email, external services and MCP tools) without requiring user confirmation. An injected prompt can use them to carry data out: PipeLeak (Capsule Security, 2026) used the email action, and SalesBleed posted through Slack.';

  readonly dependsOnCache = ['agentInventory', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    if (ctx.cache.agentAccess !== 'ok') return { findings };
    const activeAgents = (ctx.cache.agentInventory ?? []).filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    const functions = await this.optional<FunctionRow>(
      ctx,
      `SELECT Id, DeveloperName, MasterLabel, Source, InvocationTargetType, InvocationTarget, IsConfirmationRequired FROM GenAiFunctionDefinition`,
    );
    const pluginActions = await this.optional<PluginActionRow>(ctx, `SELECT PluginId, Function FROM GenAiPluginFunctionDef`);

    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/EinsteinCopilot/home`;

    // Outbound actions with a definition row: the confirmation setting is readable.
    const definedNames = new Set<string>();
    const unconfirmed: { label: string; kind: Kind }[] = [];
    for (const fn of functions) {
      if (fn.Source) definedNames.add(fn.Source.toLowerCase());
      definedNames.add(fn.DeveloperName.toLowerCase());
      const kind = outboundKind(fn);
      if (kind && fn.IsConfirmationRequired !== true) unconfirmed.push({ label: fn.MasterLabel ?? fn.DeveloperName, kind });
    }

    if (unconfirmed.length > 0) {
      findings.push({
        id: 'agent-outbound-actions-unconfirmed',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unconfirmed.length} agent action(s) can send data out of the org without user confirmation`,
        detail:
          `${unconfirmed.length} Agentforce action(s) send a Slack message, an email or a call to an external ` +
          `service, and none of them requires the user to confirm first. If an agent reads text an outsider ` +
          `wrote (a lead, a case, an email), an injected instruction can use these actions to send whatever the ` +
          `agent can read to an address or channel the attacker chooses. PipeLeak used the email action this way; ` +
          `SalesBleed used Slack. Rendered links and Slack link previews are further ways out that this ` +
          `metadata audit cannot see.`,
        remediation:
          'Turn on "Require user confirmation" for each of these actions, or remove them from agents that read ' +
          'untrusted input. Keep agents that send messages separate from agents that can query broadly.',
        affectedItems: unconfirmed.map((u) => ({ label: u.label, url: setupUrl, note: `${u.kind}, no confirmation required` })),
      });
    }

    // Standard outbound actions attached to topics with no definition row to read the setting from.
    const unverified = [...new Set(
      pluginActions
        .map((pa) => pa.Function)
        .filter((n): n is string => !!n && !definedNames.has(n.toLowerCase()))
        .filter((n) => outboundKind({ DeveloperName: n, Source: null, InvocationTargetType: null, InvocationTarget: null }) !== null),
    )];

    if (unverified.length > 0) {
      findings.push({
        id: 'agent-outbound-actions-unverified',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unverified.length} standard outbound action(s) in use; confirmation setting not readable`,
        detail:
          `Topics in this org use ${unverified.length} standard action(s) that post to Slack or send email ` +
          `(${unverified.join(', ')}). The platform does not expose their confirmation setting through Tooling, ` +
          `so this audit cannot tell whether a user must approve each message. Salesforce changed the default for ` +
          `some Agentforce Slack actions to require confirmation after SalesBleed; agents configured earlier may ` +
          `not have picked that up.`,
        remediation:
          'Open each agent that uses these actions in Agentforce Builder and confirm that user confirmation is ' +
          'required before a message is sent. Remove the action where the agent does not need to post.',
        affectedItems: unverified.map((n) => ({ label: n, url: setupUrl, note: 'standard action, confirmation not verified' })),
      });
    }

    return { findings };
  }

  private async optional<T>(ctx: AuditContext, soql: string): Promise<T[]> {
    try {
      return await ctx.tooling.query<T>(soql);
    } catch {
      return [];
    }
  }
}
