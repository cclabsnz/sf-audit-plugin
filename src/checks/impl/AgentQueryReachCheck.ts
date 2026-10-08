import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { loadAgentGraph, type FunctionRow, type PluginRow } from '../support/agentGraph.js';

// Standard names are namespaced (EmployeeCopilot__GeneralCRM); local copies carry them in Source
// or as a DeveloperName prefix with an id suffix (GeneralCRM_16jgK000002FoUn). Match by suffix
// so the namespace and local suffixes are not load-bearing.
const GENERAL_CRM = /(^|__)GeneralCRM(_|$)/i;
const QUERY_RECORDS = /(^|__)QueryRecords(WithAggregate)?(_|$)/i;

const matches = (re: RegExp, ...names: (string | null | undefined)[]) => names.some((n) => !!n && re.test(n));
const isQueryAction = (fn: FunctionRow) => matches(QUERY_RECORDS, fn.Source, fn.DeveloperName);
const topicLabel = (t: PluginRow) => t.MasterLabel ?? t.DeveloperName;

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

    const graph = await loadAgentGraph(ctx, activeAgents);
    if (!graph) return { findings };

    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/EinsteinCopilot/home`;
    for (const planner of graph.planners) {
      const reasons = new Set<string>();
      for (const topic of graph.topicsByPlanner.get(planner.Id) ?? []) {
        if (matches(GENERAL_CRM, topic.Source, topic.DeveloperName)) reasons.add('General CRM topic');
        const actions = graph.actionsByTopic.get(topic.Id) ?? [];
        const unresolved = graph.unresolvedActionsByTopic.get(topic.Id) ?? [];
        if (actions.some(isQueryAction) || unresolved.some((n) => QUERY_RECORDS.test(n))) {
          reasons.add(topic.Id.startsWith('planner:') ? 'Query Records action' : `Query Records action (topic ${topicLabel(topic)})`);
        }
      }
      if (reasons.size === 0) continue;
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
          `channels; see agent-outbound-actions.` +
          (graph.activeOnly ? '' : ' (Active versions could not be told apart, so every agent version was checked.)'),
        remediation:
          'Remove the General CRM topic or the Query Records action from agents that do not need open-ended ' +
          'querying, and replace it with actions that read only the records the job needs. Where it must stay, ' +
          'keep the agent away from untrusted input and trim its run-as user\'s object and field access.',
        affectedItems: [{ label: `${label} (${planner.DeveloperName})`, url: setupUrl, note: why }],
      });
    }

    // Query Records on topics no agent references. Only meaningful when every planner was in
    // scope: once narrowed to active versions, inactive versions' topics are expected here.
    if (findings.length === 0 && !graph.activeOnly) {
      const orphans = [...graph.actionsByTopic.entries()]
        .filter(([topicId, fns]) => !graph.liveTopicIds.has(topicId) && fns.some(isQueryAction))
        .map(([topicId]) => topicId);
      for (const [topicId, names] of graph.unresolvedActionsByTopic) {
        if (!graph.liveTopicIds.has(topicId) && names.some((n) => QUERY_RECORDS.test(n)) && !orphans.includes(topicId)) orphans.push(topicId);
      }
      if (orphans.length > 0) {
        findings.push({
          id: 'agent-query-reach-unmapped',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `Query Records is configured on ${orphans.length} topic(s) not tied to a specific agent`,
          detail:
            `The open-ended Query Records action is attached to ${orphans.length} topic(s), but the platform did ` +
            `not expose a link from those topics to an agent. ${activeAgents.length} active agent(s) exist, so ` +
            `confirm in Agentforce Builder whether any of them uses these topics.`,
          remediation:
            'Open each active agent in Agentforce Builder and check its topics for Query Records. Remove it where ' +
            'the agent does not need open-ended querying.',
          affectedItems: orphans.map((id) => ({ label: id, url: setupUrl, note: 'topic with Query Records' })),
        });
      }
    }

    return { findings };
  }
}
