import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { AgentDefinition, AgentUser } from '../../context/AuditCache.js';
import { isApiError } from '../../api/ApiError.js';

// BotDefinition rows carry both classic Einstein Bots and Agentforce agents; Type
// separates them. BotUserId is the run-as user where the platform exposes it.
interface BotDefinitionRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  Type?: string | null;
  BotUserId?: string | null;
}

interface BotVersionRecord {
  Id: string;
  BotDefinitionId: string;
  Status: string;
  VersionNumber: number;
}

interface GenAiPlannerRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
}

// User row (agent user population) with its child PermissionSetAssignment records.
interface AgentUserRecord {
  Id: string;
  Username: string;
  IsActive: boolean;
  Profile: { Name: string } | null;
  PermissionSetAssignments?: { records: { PermissionSetId: string }[] } | null;
}

interface PslAssignRecord {
  AssigneeId: string;
  PermissionSetLicense: { MasterLabel: string } | null;
}

interface RunAsUserStatusRecord {
  Id: string;
  IsActive: boolean;
}

// BotDefinition.Type values that denote an Agentforce / GenAI agent rather than a
// classic Einstein Bot. Matched case-insensitively; anything else (typically 'Bot')
// is treated as a classic bot. LIKE-style matching so exact enum spellings across
// releases are not load-bearing.
const AGENT_TYPE_HINTS = ['agent', 'einsteinservice', 'einsteincopilot', 'genai', 'copilot'];

// Permission set license labels that grant Agentforce / Einstein Agent capability.
// Substring match so exact SKU names are not load-bearing.
const AGENT_LICENSE_HINTS = ['agentforce', 'einstein agent'];

// A Tooling error whose cause is "the object does not exist" (feature absent) rather
// than a transient/permission failure. Mirrors classifyEventLogAccessError's not-enabled arm.
function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

export class AgentInventoryCheck implements SecurityCheck {
  readonly id = 'agent-inventory';
  readonly name = 'Agentforce Agent Inventory';
  readonly category = 'AI & Agents';
  readonly description =
    'Inventories Agentforce agents and classic Einstein Bots, their active versions, run-as users, and the users licensed to run agents.';

  readonly populatesCache = ['agentInventory', 'agentUsers', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Step 1: BotDefinition is the entry query. If the object itself does not exist the
    // org has no Agentforce/Bot feature — degrade to 'not-enabled' and stay silent.
    let bots: BotDefinitionRecord[];
    try {
      bots = await this.queryBotDefinitions(ctx);
    } catch (e) {
      if (isMissingObjectError(e)) {
        ctx.cache.agentAccess = 'not-enabled';
      } else {
        ctx.cache.agentAccess = 'unknown';
      }
      ctx.cache.agentInventory = [];
      ctx.cache.agentUsers = [];
      return { findings };
    }

    // Step 2+: active versions, planner definitions, and agent users. Any failure here
    // (the objects exist, so this is not 'not-enabled') means we could not fully build the
    // inventory — record 'unknown' and return no findings rather than assert a partial view.
    let versions: BotVersionRecord[];
    let agentUsers: AgentUser[];
    try {
      versions = await ctx.tooling.query<BotVersionRecord>(
        `SELECT Id, BotDefinitionId, Status, VersionNumber FROM BotVersion WHERE Status = 'Active'`,
      );
      // GenAiPlannerDefinition is queried for completeness of the agent picture (Phase 2
      // action-surface work joins on it); a failure here still counts as an incomplete build.
      await ctx.tooling.query<GenAiPlannerRecord>(
        `SELECT Id, DeveloperName, MasterLabel FROM GenAiPlannerDefinition`,
      );
      agentUsers = await this.queryAgentUsers(ctx);
    } catch (e) {
      if (isMissingObjectError(e)) {
        // BotDefinition existed but a GenAI object did not: the feature is partially present
        // (e.g. classic bots without Agentforce). Treat as 'unknown' — we cannot vouch for a
        // complete agent inventory — rather than 'not-enabled'.
        ctx.cache.agentAccess = 'unknown';
      } else {
        ctx.cache.agentAccess = 'unknown';
      }
      ctx.cache.agentInventory = [];
      ctx.cache.agentUsers = [];
      return { findings };
    }

    // Build the inventory. Active version = the BotVersion (per definition) with Status Active.
    const activeVersionByBot = new Map<string, number>();
    for (const v of versions) {
      const existing = activeVersionByBot.get(v.BotDefinitionId);
      if (existing === undefined || v.VersionNumber > existing) {
        activeVersionByBot.set(v.BotDefinitionId, v.VersionNumber);
      }
    }

    const runAsIds = bots.map((b) => b.BotUserId).filter((id): id is string => !!id);
    const runAsStatus = await this.queryRunAsUserStatus(ctx, runAsIds);

    const inventory: AgentDefinition[] = bots.map((b) => {
      const activeVersion = activeVersionByBot.get(b.Id);
      const runAsUserId = b.BotUserId ?? undefined;
      const runAsUserActive =
        runAsUserId !== undefined && runAsStatus.has(runAsUserId)
          ? runAsStatus.get(runAsUserId)
          : undefined;
      return {
        developerName: b.DeveloperName,
        label: b.MasterLabel,
        type: this.classifyType(b.Type),
        isActive: activeVersion !== undefined,
        activeVersion,
        runAsUserId,
        runAsUserActive,
      };
    });

    ctx.cache.agentInventory = inventory;
    ctx.cache.agentUsers = agentUsers;
    ctx.cache.agentAccess = 'ok';

    const agents = inventory.filter((a) => a.type === 'agent');
    const activeAgents = agents.filter((a) => a.isActive);

    if (inventory.length === 0) {
      // Feature present but nothing configured: no noise, cache already records 'ok'.
      return { findings };
    }

    // Info: the inventory itself is the product.
    findings.push({
      id: 'agent-inventory-summary',
      category: this.category,
      riskLevel: 'INFO',
      title: `Agentforce inventory: ${agents.length} agent(s), ${activeAgents.length} active, ${agentUsers.length} agent user(s)`,
      detail:
        `Found ${inventory.length} bot/agent definition(s): ${agents.length} Agentforce agent(s) ` +
        `(${activeAgents.length} with an active version) and ${inventory.length - agents.length} classic Einstein Bot(s). ` +
        `${agentUsers.length} user(s) are licensed to run agents (Einstein Agent User profile or an Agentforce / Einstein Agent permission set license). ` +
        `Each active agent executes as a run-as user whose data access defines the blast radius of a prompt injection.`,
      remediation:
        'Confirm every active agent is expected and documented, that its run-as user follows least privilege, and that the agent users list contains no stale accounts.',
      affectedItems: inventory.map((a) => ({
        label: `${a.label} (${a.developerName})`,
        note:
          `${a.type === 'agent' ? 'Agentforce agent' : 'classic Einstein Bot'} | ` +
          `${a.isActive ? `active v${a.activeVersion}` : 'no active version'}` +
          (a.runAsUserId ? ` | run-as: ${a.runAsUserId}` : ''),
      })),
    });

    // Medium: an active agent whose run-as user is inactive or frozen. The agent stays
    // reachable but its identity is disabled — a latent misconfiguration and, if reactivated
    // without review, a way to smuggle access back in.
    const brokenRunAs = inventory.filter(
      (a) => a.type === 'agent' && a.isActive && a.runAsUserActive === false,
    );
    for (const a of brokenRunAs) {
      findings.push({
        id: `agent-inventory-runas-inactive-${a.developerName}`,
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `Active agent "${a.label}" runs as an inactive or frozen user`,
        detail:
          `The Agentforce agent "${a.label}" (${a.developerName}) has an active version but its run-as user ` +
          `is inactive or frozen. Requests to the agent will fail, and if the user is later reactivated its ` +
          `permissions take effect again without a fresh review.`,
        remediation:
          'Confirm the run-as user should be disabled. If the agent is still needed, assign an active, least-privilege run-as user; otherwise deactivate the agent version.',
        affectedItems: [
          {
            label: `${a.label} (${a.developerName})`,
            url: a.runAsUserId ? `${baseUrl}/${a.runAsUserId}` : undefined,
            note: `run-as user ${a.runAsUserId ?? 'unknown'} is inactive/frozen`,
          },
        ],
      });
    }

    return { findings };
  }

  private classifyType(type: string | null | undefined): 'agent' | 'classic-bot' {
    const t = (type ?? '').toLowerCase();
    return AGENT_TYPE_HINTS.some((h) => t.includes(h)) ? 'agent' : 'classic-bot';
  }

  // BotDefinition query with a defensive fallback: if Type/BotUserId are not queryable in
  // this org/release (MALFORMED_QUERY on the field), retry with the minimal field set rather
  // than throw. A genuinely missing object still throws and is handled by the caller.
  private async queryBotDefinitions(ctx: AuditContext): Promise<BotDefinitionRecord[]> {
    try {
      return await ctx.tooling.query<BotDefinitionRecord>(
        `SELECT Id, DeveloperName, MasterLabel, Type, BotUserId FROM BotDefinition`,
      );
    } catch (e) {
      if (isApiError(e) && /MALFORMED_QUERY|INVALID_FIELD/i.test(e.errorCode)) {
        return ctx.tooling.query<BotDefinitionRecord>(
          `SELECT Id, DeveloperName, MasterLabel FROM BotDefinition`,
        );
      }
      throw e;
    }
  }

  // Users on the Einstein Agent User profile OR holding an Agentforce / Einstein Agent
  // permission set license, with their PermissionSetAssignment ids and license labels.
  private async queryAgentUsers(ctx: AuditContext): Promise<AgentUser[]> {
    const licenseLike = AGENT_LICENSE_HINTS.map(
      (h) => `PermissionSetLicense.MasterLabel LIKE '%${h}%'`,
    ).join(' OR ');

    // License assignments first, so the User filter can include those assignees.
    const licenseAssigns = await ctx.soql.queryAll<PslAssignRecord>(
      `SELECT AssigneeId, PermissionSetLicense.MasterLabel
       FROM PermissionSetLicenseAssign
       WHERE ${licenseLike}
       LIMIT 500`,
    );

    const licenseNamesByUser = new Map<string, string[]>();
    for (const a of licenseAssigns) {
      const label = a.PermissionSetLicense?.MasterLabel;
      if (!label) continue;
      const list = licenseNamesByUser.get(a.AssigneeId) ?? [];
      list.push(label);
      licenseNamesByUser.set(a.AssigneeId, list);
    }

    const licensedIds = [...licenseNamesByUser.keys()];
    const idInClause = licensedIds.length
      ? ` OR Id IN (${licensedIds.map((id) => `'${id}'`).join(',')})`
      : '';

    const users = await ctx.soql.queryAll<AgentUserRecord>(
      `SELECT Id, Username, IsActive, Profile.Name,
              (SELECT PermissionSetId FROM PermissionSetAssignments)
       FROM User
       WHERE Profile.Name = 'Einstein Agent User'${idInClause}
       LIMIT 500`,
    );

    return users.map((u) => ({
      userId: u.Id,
      username: u.Username,
      profileName: u.Profile?.Name ?? '',
      isActive: u.IsActive,
      permissionSetIds: (u.PermissionSetAssignments?.records ?? []).map((r) => r.PermissionSetId),
      permissionSetLicenseNames: licenseNamesByUser.get(u.Id) ?? [],
    }));
  }

  // Resolve which run-as users are active (and not frozen). A frozen user has an active
  // IsActive flag but a UserLogin.IsFrozen = true row, so exclude those from the "active" set.
  private async queryRunAsUserStatus(
    ctx: AuditContext,
    runAsIds: string[],
  ): Promise<Map<string, boolean>> {
    const status = new Map<string, boolean>();
    if (runAsIds.length === 0) return status;

    const idList = runAsIds.map((id) => `'${id}'`).join(',');
    const rows = await ctx.soql.queryAll<RunAsUserStatusRecord>(
      `SELECT Id, IsActive
       FROM User
       WHERE Id IN (${idList})
         AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)`,
    );
    // Rows returned = active and not frozen. Any run-as id absent from the result set is
    // therefore inactive or frozen.
    const activeIds = new Set(rows.filter((r) => r.IsActive).map((r) => r.Id));
    for (const id of runAsIds) status.set(id, activeIds.has(id));
    return status;
  }
}
