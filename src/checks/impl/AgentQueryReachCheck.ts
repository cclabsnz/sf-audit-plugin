import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// Agentforce planner (the agent's reasoning definition) and the link tables that attach topics
// (plugins) and actions (functions) to it. Field names verified read-only against a v67.0 org.
interface PlannerRow { Id: string; DeveloperName: string; MasterLabel?: string | null }
interface PlannerTopicRow { PlannerId: string; Plugin: string | null }
interface PluginRow { Id: string; DeveloperName: string; MasterLabel?: string | null; Source?: string | null; PlannerId?: string | null }
interface PluginActionRow { PluginId: string; Function: string | null }
interface FunctionRow { Id: string; DeveloperName: string; MasterLabel?: string | null; Source?: string | null; PlannerId?: string | null; PluginId?: string | null }

// Standard names are namespaced (EmployeeCopilot__GeneralCRM); local copies carry them in Source
// or as a DeveloperName prefix. Match by suffix so the namespace and local suffixes are not
// load-bearing.
const GENERAL_CRM = /(^|__)GeneralCRM(_|$)/i;
const QUERY_RECORDS = /(^|__)QueryRecords(WithAggregate)?(_|$)/i;

const isGeneralCrm = (...names: (string | null | undefined)[]) => names.some((n) => !!n && GENERAL_CRM.test(n));
const isQueryRecords = (...names: (string | null | undefined)[]) => names.some((n) => !!n && QUERY_RECORDS.test(n));

export class AgentQueryReachCheck implements SecurityCheck {
  readonly id = 'agent-query-reach';
  readonly name = 'Agent Query Reach';
  readonly category = 'AI & Agents';
  readonly description =
    'Flags agents that carry the standard General CRM topic or a Query Records action, which lets an injected prompt query any object the run-as user can read. This open-ended query is how SalesBleed (Zenity Labs, 2026) read Account data from a poisoned Web-to-Lead record.';

  readonly dependsOnCache = ['agentInventory', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    if (ctx.cache.agentAccess !== 'ok') return { findings };
    const activeAgents = (ctx.cache.agentInventory ?? []).filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    // The planner list is required; without it there is nothing to attribute. The link tables
    // are optional: each one that fails just contributes no evidence.
    let planners: PlannerRow[];
    try {
      planners = await ctx.tooling.query<PlannerRow>(`SELECT Id, DeveloperName, MasterLabel FROM GenAiPlannerDefinition`);
    } catch {
      return { findings };
    }
    const plannerTopics = await this.optional<PlannerTopicRow>(ctx, `SELECT PlannerId, Plugin FROM GenAiPlannerFunctionDef`);
    const plugins = await this.optional<PluginRow>(ctx, `SELECT Id, DeveloperName, MasterLabel, Source, PlannerId FROM GenAiPluginDefinition`);
    const pluginActions = await this.optional<PluginActionRow>(ctx, `SELECT PluginId, Function FROM GenAiPluginFunctionDef`);
    const functions = await this.optional<FunctionRow>(ctx, `SELECT Id, DeveloperName, MasterLabel, Source, PlannerId, PluginId FROM GenAiFunctionDefinition`);

    // Which plugins (topics) carry a Query Records action, by id.
    const queryPluginIds = new Set<string>();
    for (const pa of pluginActions) if (isQueryRecords(pa.Function)) queryPluginIds.add(pa.PluginId);
    for (const fn of functions) if (fn.PluginId && isQueryRecords(fn.Source, fn.DeveloperName)) queryPluginIds.add(fn.PluginId);

    // A planner's topic link may name a plugin by developer name or by id.
    const pluginByRef = new Map<string, PluginRow>();
    for (const p of plugins) { pluginByRef.set(p.Id, p); pluginByRef.set(p.DeveloperName, p); }

    const attributedPluginIds = new Set<string>();
    const reasonsByPlanner = new Map<string, Set<string>>();
    const addReason = (plannerId: string, reason: string) => {
      if (!reasonsByPlanner.has(plannerId)) reasonsByPlanner.set(plannerId, new Set());
      reasonsByPlanner.get(plannerId)!.add(reason);
    };
    const considerPlugin = (plannerId: string, p: PluginRow | undefined, rawName: string | null) => {
      if (isGeneralCrm(rawName, p?.Source, p?.DeveloperName)) addReason(plannerId, 'General CRM topic');
      if (p) {
        attributedPluginIds.add(p.Id);
        if (queryPluginIds.has(p.Id)) addReason(plannerId, `Query Records action (topic ${p.MasterLabel ?? p.DeveloperName})`);
      }
    };

    for (const t of plannerTopics) considerPlugin(t.PlannerId, t.Plugin ? pluginByRef.get(t.Plugin) : undefined, t.Plugin);
    for (const p of plugins) if (p.PlannerId) considerPlugin(p.PlannerId, p, null);
    for (const fn of functions) {
      if (fn.PlannerId && isQueryRecords(fn.Source, fn.DeveloperName)) {
        addReason(fn.PlannerId, 'Query Records action');
        if (fn.PluginId) attributedPluginIds.add(fn.PluginId);
      }
    }

    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/EinsteinCopilot/home`;
    for (const planner of planners) {
      const reasons = reasonsByPlanner.get(planner.Id);
      if (!reasons) continue;
      const label = planner.MasterLabel ?? planner.DeveloperName;
      const why = [...reasons].join(', ');
      findings.push({
        id: `agent-query-reach-${planner.DeveloperName}`,
        category: this.category,
        riskLevel: 'HIGH',
        title: `Agent "${label}" can run open-ended record queries`,
        detail:
          `The agent "${label}" (${planner.DeveloperName}) has: ${why}. The standard General CRM topic and its ` +
          `Query Records action let the model decide at run time which object to query, so an instruction ` +
          `hidden in any record the agent reads (a Web-to-Lead or Web-to-Case submission, an inbound email, a ` +
          `chat transcript) can make it query any object its run-as user can see. This is how SalesBleed read ` +
          `Account data from a poisoned lead. Whether that data can then leave depends on the agent's output ` +
          `channels; see agent-outbound-actions.`,
        remediation:
          'Remove the General CRM topic or the Query Records action from agents that do not need open-ended ' +
          'querying, and replace it with actions that read only the records the job needs. Where it must stay, ' +
          'keep the agent away from untrusted input and trim its run-as user\'s object and field access.',
        affectedItems: [{ label: `${label} (${planner.DeveloperName})`, url: setupUrl, note: why }],
      });
    }

    // Query Records exists on a topic we could not tie to any planner.
    const unmapped = [...queryPluginIds].filter((id) => !attributedPluginIds.has(id));
    if (findings.length === 0 && unmapped.length > 0) {
      findings.push({
        id: 'agent-query-reach-unmapped',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `Query Records is configured on ${unmapped.length} topic(s) not tied to a specific agent`,
        detail:
          `The open-ended Query Records action is attached to ${unmapped.length} topic(s), but the platform did ` +
          `not expose a link from those topics to an agent. ${activeAgents.length} active agent(s) exist, so ` +
          `confirm in Agentforce Builder whether any of them uses these topics.`,
        remediation:
          'Open each active agent in Agentforce Builder and check its topics for Query Records. Remove it where ' +
          'the agent does not need open-ended querying.',
        affectedItems: unmapped.map((id) => {
          const p = pluginByRef.get(id);
          return { label: p ? (p.MasterLabel ?? p.DeveloperName) : id, url: setupUrl, note: 'topic with Query Records' };
        }),
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
