import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { loadAgentGraph, type FunctionRow } from '../support/agentGraph.js';

// Invocation types that hand data to something outside the org.
const EXTERNAL_TYPES = new Set(['slack', 'externalservice', 'externalconnector', 'mcptool', 'platformmcptool']);
// Standard invocable actions that send email (Flow's core "Send Email" and email alerts).
const EMAIL_TARGETS = new Set(['emailsimple', 'emailalert']);
// Standard Slack actions that post a message somewhere. Names verified from the
// GenAiPluginFunctionDef.Function picklist (v67.0).
const SLACK_SEND = /(^|__)(ReplyInThread|SendMessageAsAgent|SendMessageToSlackChannel|SendSlackDirectMessage)(_|$)/i;
// "SendClaimEmail", "SendVisitSummaryEmail": a name that sends rather than drafts an email.
const SEND_EMAIL_NAME = /(^|__|_)Send\w*Email/i;
// Flow action types that send data out. Read from the active flow version's metadata, because
// an agent's Flow action names the FlowDefinition Id, not what the flow does.
const FLOW_OUTBOUND: Record<string, Kind> = {
  emailsimple: 'email',
  emailalert: 'email',
  externalservice: 'external service',
};
// Flows inspected per run. Each needs two Tooling reads; past this the rest are skipped.
const MAX_FLOWS = 25;

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

interface FlowDefinitionRow { Id: string; DeveloperName: string; ActiveVersionId?: string | null }
interface FlowVersionRow { Id: string; Metadata?: { actionCalls?: { actionType?: string | null; actionName?: string | null }[] } | null }

export class AgentOutboundActionsCheck implements SecurityCheck {
  readonly id = 'agent-outbound-actions';
  readonly name = 'Agent Outbound Actions';
  readonly category = 'AI & Agents';
  readonly description =
    'Flags agent actions that send data out of the org (Slack messages, email, external services and MCP tools, including Flow actions whose flow sends email or calls an external service) without requiring user confirmation. An injected prompt can use them to carry data out: PipeLeak (Capsule Security, 2026) used the email action, and SalesBleed posted through Slack.';

  readonly dependsOnCache = ['agentInventory', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    if (ctx.cache.agentAccess !== 'ok') return { findings };
    const activeAgents = (ctx.cache.agentInventory ?? []).filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    const graph = await loadAgentGraph(ctx, activeAgents);
    if (!graph) return { findings };

    // Every action on a live topic, once each.
    const live = new Map<string, FunctionRow>();
    for (const topicId of graph.liveTopicIds) for (const fn of graph.actionsByTopic.get(topicId) ?? []) live.set(fn.Id, fn);

    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/EinsteinCopilot/home`;
    const unconfirmed: { label: string; kind: Kind; via?: string }[] = [];
    const flowActions: FunctionRow[] = [];
    for (const fn of live.values()) {
      if (fn.IsConfirmationRequired === true) continue;
      const kind = outboundKind(fn);
      if (kind) unconfirmed.push({ label: fn.MasterLabel ?? fn.DeveloperName, kind });
      else if ((fn.InvocationTargetType ?? '').toLowerCase() === 'flow' && fn.InvocationTarget) flowActions.push(fn);
    }
    for (const { fn, kind, flowName } of await this.outboundFlows(ctx, flowActions)) {
      unconfirmed.push({ label: fn.MasterLabel ?? fn.DeveloperName, kind, via: flowName });
    }

    if (unconfirmed.length > 0) {
      findings.push({
        id: 'agent-outbound-actions-unconfirmed',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unconfirmed.length} agent action(s) can send data out of the org without user confirmation`,
        detail:
          `${unconfirmed.length} action(s) on active agents send a Slack message, an email or a call to an ` +
          `external service, and none of them requires the user to confirm first. If an agent reads text an ` +
          `outsider wrote (a lead, a case, an email), an injected instruction can use these actions to send ` +
          `whatever the agent can read to an address or channel the attacker chooses. PipeLeak used the email ` +
          `action this way; SalesBleed used Slack. Flow actions are judged by what the active flow version does; ` +
          `Apex actions are not inspected. Rendered links and Slack link previews are further ways out that this ` +
          `metadata audit cannot see.`,
        remediation:
          'Turn on "Require user confirmation" for each of these actions, or remove them from agents that read ' +
          'untrusted input. Keep agents that send messages separate from agents that can query broadly.',
        affectedItems: unconfirmed.map((u) => ({
          label: u.label,
          url: setupUrl,
          note: `${u.kind}${u.via ? ` (flow ${u.via})` : ''}, no confirmation required`,
        })),
      });
    }

    // Standard outbound actions a live topic names with no local definition to read the setting from.
    const unverified = [...new Set(
      [...graph.liveTopicIds]
        .flatMap((id) => graph.unresolvedActionsByTopic.get(id) ?? [])
        .filter((n) => outboundKind({ DeveloperName: n, Source: null, InvocationTargetType: null, InvocationTarget: null }) !== null),
    )];

    if (unverified.length > 0) {
      findings.push({
        id: 'agent-outbound-actions-unverified',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${unverified.length} standard outbound action(s) in use; confirmation setting not readable`,
        detail:
          `Topics on active agents use ${unverified.length} standard action(s) that post to Slack or send email ` +
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

  // For Flow actions, read the active version of each flow and report the first outbound step.
  // An agent's Flow action targets the FlowDefinition by Id (300...) or by API name.
  private async outboundFlows(
    ctx: AuditContext,
    actions: FunctionRow[],
  ): Promise<{ fn: FunctionRow; kind: Kind; flowName: string }[]> {
    const out: { fn: FunctionRow; kind: Kind; flowName: string }[] = [];
    const seen = new Map<string, { kind: Kind; flowName: string } | null>();
    for (const fn of actions) {
      const target = fn.InvocationTarget!;
      if (!seen.has(target)) {
        if (seen.size >= MAX_FLOWS) break;
        seen.set(target, await this.inspectFlow(ctx, target));
      }
      const hit = seen.get(target);
      if (hit) out.push({ fn, ...hit });
    }
    return out;
  }

  private async inspectFlow(ctx: AuditContext, target: string): Promise<{ kind: Kind; flowName: string } | null> {
    try {
      const where = /^300[A-Za-z0-9]{12}([A-Za-z0-9]{3})?$/.test(target)
        ? `Id = '${target}'`
        : `DeveloperName = '${target.split('__').pop()!.replace(/'/g, '')}'`;
      const [def] = await ctx.tooling.query<FlowDefinitionRow>(`SELECT Id, DeveloperName, ActiveVersionId FROM FlowDefinition WHERE ${where}`);
      if (!def?.ActiveVersionId) return null;
      // Tooling returns Metadata for one Flow row per query.
      const [version] = await ctx.tooling.query<FlowVersionRow>(`SELECT Id, Metadata FROM Flow WHERE Id = '${def.ActiveVersionId}'`);
      for (const call of version?.Metadata?.actionCalls ?? []) {
        const type = (call.actionType ?? '').toLowerCase();
        const name = (call.actionName ?? '').toLowerCase();
        const kind = FLOW_OUTBOUND[type] ?? (type.includes('slack') || name.includes('slack') ? 'Slack message' : undefined);
        if (kind) return { kind, flowName: def.DeveloperName };
      }
      return null;
    } catch {
      // Flow metadata unreadable: make no claim about this action.
      return null;
    }
  }
}
