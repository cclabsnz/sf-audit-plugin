import type { AuditContext, AgentDefinition } from '@cclabsnz/sf-core';

// The Agentforce configuration graph as the Tooling API exposes it, resolved to what is live:
// planners (one per agent version), the topics (plugins) attached to them, and the actions
// (functions) attached to those topics. Shapes verified read-only against a v67.0 org on
// 2026-10-09:
//   - every agent version gets its own planner, named `<BotDefinition.DeveloperName>_v<n>`;
//   - GenAiPlannerFunctionDef.Plugin holds the topic's Id, not its name;
//   - GenAiPluginFunctionDef.Function holds the action's Id, not its name;
//   - local copies of standard topics/actions carry the standard name in Source (actions) or
//     as a DeveloperName prefix with an id suffix (topics, e.g. GeneralCRM_16jgK000002FoUn).

export interface PlannerRow { Id: string; DeveloperName: string; MasterLabel?: string | null }
export interface PlannerTopicRow { PlannerId: string; Plugin: string | null }
export interface PluginRow { Id: string; DeveloperName: string; MasterLabel?: string | null; Source?: string | null; PlannerId?: string | null }
export interface PluginActionRow { PluginId: string; Function: string | null }
export interface FunctionRow {
  Id: string;
  DeveloperName: string;
  MasterLabel?: string | null;
  Source?: string | null;
  PlannerId?: string | null;
  PluginId?: string | null;
  InvocationTargetType?: string | null;
  InvocationTarget?: string | null;
  IsConfirmationRequired?: boolean | null;
}

export interface AgentGraph {
  /** Planners of active agent versions; every planner when versions cannot be matched. */
  planners: PlannerRow[];
  /** Whether `planners` was narrowed to active versions (false = fell back to all). */
  activeOnly: boolean;
  /** Topics attached to each planner in `planners`, by planner Id. */
  topicsByPlanner: Map<string, PluginRow[]>;
  /** Actions attached to each topic, by topic Id. */
  actionsByTopic: Map<string, FunctionRow[]>;
  /** Standard action names a topic references with no local definition row, by topic Id. */
  unresolvedActionsByTopic: Map<string, string[]>;
  /** Every topic Id reachable from `planners`. */
  liveTopicIds: Set<string>;
}

async function optional<T>(ctx: AuditContext, soql: string): Promise<T[]> {
  try {
    return await ctx.tooling.query<T>(soql);
  } catch {
    return [];
  }
}

/** Null when the planner object itself is unavailable (feature absent or no access). */
export async function loadAgentGraph(ctx: AuditContext, activeAgents: AgentDefinition[]): Promise<AgentGraph | null> {
  let allPlanners: PlannerRow[];
  try {
    allPlanners = await ctx.tooling.query<PlannerRow>(`SELECT Id, DeveloperName, MasterLabel FROM GenAiPlannerDefinition`);
  } catch {
    return null;
  }
  const plannerTopics = await optional<PlannerTopicRow>(ctx, `SELECT PlannerId, Plugin FROM GenAiPlannerFunctionDef`);
  const plugins = await optional<PluginRow>(ctx, `SELECT Id, DeveloperName, MasterLabel, Source, PlannerId FROM GenAiPluginDefinition`);
  const pluginActions = await optional<PluginActionRow>(ctx, `SELECT PluginId, Function FROM GenAiPluginFunctionDef`);
  const functions = await optional<FunctionRow>(
    ctx,
    `SELECT Id, DeveloperName, MasterLabel, Source, PlannerId, PluginId, InvocationTargetType, InvocationTarget, IsConfirmationRequired FROM GenAiFunctionDefinition`,
  );

  // Narrow to the planner of each agent's active version. If no planner follows the
  // `<agent>_v<n>` convention, keep them all rather than report nothing.
  const activeNames = new Set(
    activeAgents.filter((a) => a.activeVersion !== undefined).map((a) => `${a.developerName}_v${a.activeVersion}`.toLowerCase()),
  );
  const active = allPlanners.filter((p) => activeNames.has(p.DeveloperName.toLowerCase()));
  const planners = active.length > 0 ? active : allPlanners;
  const plannerIds = new Set(planners.map((p) => p.Id));

  // A topic reference may be the topic's Id or its developer name.
  const pluginByRef = new Map<string, PluginRow>();
  for (const p of plugins) { pluginByRef.set(p.Id, p); pluginByRef.set(p.DeveloperName, p); }

  const topicsByPlanner = new Map<string, PluginRow[]>();
  const attach = (plannerId: string, topic: PluginRow) => {
    const list = topicsByPlanner.get(plannerId) ?? [];
    if (!list.some((t) => t.Id === topic.Id)) list.push(topic);
    topicsByPlanner.set(plannerId, list);
  };
  for (const t of plannerTopics) {
    if (!plannerIds.has(t.PlannerId) || !t.Plugin) continue;
    // An unresolved reference is a standard topic named directly (no local copy).
    attach(t.PlannerId, pluginByRef.get(t.Plugin) ?? { Id: t.Plugin, DeveloperName: t.Plugin, Source: t.Plugin });
  }
  for (const p of plugins) if (p.PlannerId && plannerIds.has(p.PlannerId)) attach(p.PlannerId, p);

  const liveTopicIds = new Set([...topicsByPlanner.values()].flat().map((t) => t.Id));

  // Actions per topic: definition rows by PluginId, plus link rows resolved by Id.
  const functionById = new Map(functions.map((f) => [f.Id, f]));
  const actionsByTopic = new Map<string, FunctionRow[]>();
  const unresolvedActionsByTopic = new Map<string, string[]>();
  const addAction = (topicId: string, fn: FunctionRow) => {
    const list = actionsByTopic.get(topicId) ?? [];
    if (!list.some((x) => x.Id === fn.Id)) list.push(fn);
    actionsByTopic.set(topicId, list);
  };
  for (const fn of functions) if (fn.PluginId) addAction(fn.PluginId, fn);
  for (const pa of pluginActions) {
    if (!pa.Function) continue;
    const fn = functionById.get(pa.Function);
    if (fn) addAction(pa.PluginId, fn);
    else {
      const list = unresolvedActionsByTopic.get(pa.PluginId) ?? [];
      list.push(pa.Function);
      unresolvedActionsByTopic.set(pa.PluginId, list);
    }
  }
  // Actions attached straight to a planner (no topic) count under a pseudo-topic per planner.
  for (const fn of functions) {
    if (fn.PlannerId && plannerIds.has(fn.PlannerId) && !fn.PluginId) {
      const pseudo = `planner:${fn.PlannerId}`;
      attach(fn.PlannerId, { Id: pseudo, DeveloperName: pseudo });
      liveTopicIds.add(pseudo);
      addAction(pseudo, fn);
    }
  }

  return { planners, activeOnly: active.length > 0, topicsByPlanner, actionsByTopic, unresolvedActionsByTopic, liveTopicIds };
}
