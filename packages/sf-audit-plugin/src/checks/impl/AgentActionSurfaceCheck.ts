import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

// One GenAI action (function). GenAiFunction / GenAiFunctionDefinition expose the same
// core fields across releases; we query defensively and fall back between them. Invocation
// fields tell us whether the action can write (Apex/Flow) versus only read/reference.
interface GenAiFunctionRow {
  Id: string;
  DeveloperName: string;
  MasterLabel?: string | null;
  InvocationTarget?: string | null;
  InvocationTargetType?: string | null;
}

// One GenAI topic (plugin). Queried for the action-surface count context; not all releases
// expose it, so failures degrade silently.
interface GenAiPluginRow {
  Id: string;
  DeveloperName: string;
  MasterLabel?: string | null;
}

// An agent carrying more than this many actions has a large, hard-to-review surface. Info
// only — a big surface is not a vulnerability by itself, but it is worth surfacing.
const ACTION_COUNT_THRESHOLD = 15;

// Invocation target types that create/update/delete (or are ambiguous enough that we treat
// them as write-capable). Apex and Flow can both mutate data; where the type string is
// unknown/ambiguous we deliberately err toward flagging and say so in the finding.
const WRITE_CAPABLE_TYPE_HINTS = ['apex', 'flow'];

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('sobject type')
  );
}

export class AgentActionSurfaceCheck implements SecurityCheck {
  readonly id = 'agent-action-surface';
  readonly name = 'Agent Action Surface';
  readonly category = 'AI & Agents';
  readonly description =
    'Inventories Agentforce topics and actions (GenAiPlugin / GenAiFunction), flagging write-capable actions (Apex/Flow that create, update, or delete) and agents with an unusually large action surface. Write-capable actions on an exposed agent let a prompt injection take actions, not just read data.';

  readonly dependsOnCache = ['agentInventory', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Gate: only run when AgentInventoryCheck confirmed the agent queries succeeded.
    if (ctx.cache.agentAccess !== 'ok') return { findings };

    const inventory = ctx.cache.agentInventory ?? [];
    const activeAgents = inventory.filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    // Query the org-wide action surface. GenAiFunction and its *Definition twin are queried
    // defensively (INVALID_TYPE on one falls back to the other); if neither resolves, the
    // feature does not expose actions in this org and we degrade silently.
    const functions = await this.queryWithFallback<GenAiFunctionRow>(
      ctx,
      'GenAiFunction',
      'SELECT Id, DeveloperName, MasterLabel, InvocationTarget, InvocationTargetType',
    );
    if (functions === null) return { findings };

    // Topics (plugins) are supplementary context; a failure here is non-fatal.
    const plugins =
      (await this.queryWithFallback<GenAiPluginRow>(
        ctx,
        'GenAiPlugin',
        'SELECT Id, DeveloperName, MasterLabel',
      )) ?? [];

    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/EinsteinCopilot/home`;

    // Write-capable actions across the org. We cannot resolve which specific agent owns each
    // action from Tooling alone (no reliable agent join here); Phase 3 chains correlate this
    // finding with agent-channel-exposure. We therefore report the write surface against the
    // active-agent population and say so explicitly.
    const writeActions = functions.filter((f) => this.isWriteCapable(f));

    if (writeActions.length > 0) {
      const agentLabels = activeAgents.map((a) => `${a.label} (${a.developerName})`);
      findings.push({
        id: 'agent-action-surface-write',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${writeActions.length} write-capable agent action(s) present across ${activeAgents.length} active agent(s)`,
        detail:
          `${writeActions.length} Agentforce action(s) invoke Apex or Flow, which can create, update, or ` +
          `delete records. (Apex and Flow invocations are treated as write-capable; where an action's ` +
          `invocation type is ambiguous it is flagged conservatively.) On an externally exposed agent, a ` +
          `successful prompt injection can drive these actions to take state-changing operations, not just ` +
          `read data. Actions: ${writeActions
            .slice(0, 20)
            .map((f) => `${f.MasterLabel ?? f.DeveloperName} [${(f.InvocationTargetType ?? 'unknown').toLowerCase()}]`)
            .join(', ')}${writeActions.length > 20 ? `, and ${writeActions.length - 20} more` : ''}.`,
        remediation:
          'Review each write-capable action: confirm the operation is intended, add guardrails/confirmation ' +
          'where it mutates sensitive data, and ensure the agent exposing it is not reachable by untrusted users. ' +
          'Correlate with channel exposure to size the real risk.',
        affectedItems: writeActions.map((f) => ({
          label: f.MasterLabel ?? f.DeveloperName,
          note:
            `${(f.InvocationTargetType ?? 'unknown').toLowerCase()} invocation` +
            (f.InvocationTarget ? ` → ${f.InvocationTarget}` : '') +
            ` | exposed via active agent(s): ${agentLabels.slice(0, 3).join(', ')}${
              agentLabels.length > 3 ? ', …' : ''
            }`,
        })),
      });
    }

    // Large action surface: informational. Reported at the org level because Tooling does not
    // give us a per-agent action join; total actions and topics both inform review effort.
    if (functions.length > ACTION_COUNT_THRESHOLD) {
      findings.push({
        id: 'agent-action-surface-count',
        category: this.category,
        riskLevel: 'INFO',
        title: `Large agent action surface: ${functions.length} actions across ${plugins.length} topic(s)`,
        detail:
          `The org exposes ${functions.length} Agentforce action(s) (threshold ${ACTION_COUNT_THRESHOLD}) across ` +
          `${plugins.length} topic(s) and ${activeAgents.length} active agent(s). A large action surface is ` +
          `harder to review and increases the chance a risky action is reachable through an agent. This is ` +
          `informational, not a vulnerability by itself.`,
        remediation:
          'Periodically review the full action catalogue. Retire unused actions and keep each agent scoped to ' +
          'the minimum set of topics and actions it needs.',
        affectedItems: [
          {
            label: `${functions.length} action(s)`,
            url: setupUrl,
            note: `${plugins.length} topic(s), ${activeAgents.length} active agent(s)`,
          },
        ],
      });
    }

    return { findings };
  }

  private isWriteCapable(f: GenAiFunctionRow): boolean {
    const type = (f.InvocationTargetType ?? '').toLowerCase();
    return WRITE_CAPABLE_TYPE_HINTS.some((h) => type.includes(h));
  }

  // Query `baseObject`, falling back to `${baseObject}Definition` when the Tooling client
  // cannot address the base object (INVALID_TYPE etc.). Returns null only when BOTH the base
  // and the *Definition twin are missing (feature absent → degrade silently).
  private async queryWithFallback<T>(
    ctx: AuditContext,
    baseObject: string,
    selectClause: string,
  ): Promise<T[] | null> {
    try {
      return await ctx.tooling.query<T>(`${selectClause} FROM ${baseObject}`);
    } catch (e1) {
      if (!isMissingObjectError(e1)) return null;
      try {
        return await ctx.tooling.query<T>(`${selectClause} FROM ${baseObject}Definition`);
      } catch {
        return null;
      }
    }
  }
}
