import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { AgentDefinition } from '@cclabsnz/sf-core';

// A live Experience Cloud (Network) site with an active guest user is a
// guest-reachable channel — anyone on the internet can hit it without a login.
interface NetworkRecord {
  Id: string;
  Name: string;
  Status: string;
  UrlPathPrefix: string | null;
  GuestUserId: string | null;
}

// Messaging channels (SMS/WhatsApp/etc). Not guest-web-reachable but a real
// inbound surface; used for inventory (info) findings.
interface MessagingChannelRecord {
  Id: string;
  MasterLabel: string | null;
  ChannelType?: string | null;
  IsActive?: boolean | null;
}

// Embedded Service deployment rows (chat/messaging-for-web). A deployment tied to
// a live site or with no authentication is a public web surface. The exact schema
// varies by release, so every field is optional and we correlate defensively.
interface EmbeddedServiceRecord {
  Id?: string;
  DeveloperName?: string | null;
  DurableId?: string | null;
  Site?: string | null;
  SiteName?: string | null;
  // Some releases expose an agent/bot binding directly on the deployment config.
  AgentDeveloperName?: string | null;
  BotDeveloperName?: string | null;
  BotUserId?: string | null;
}

// A discovered public channel, normalised for reporting.
interface PublicChannel {
  kind: 'experience-site' | 'embedded-deployment';
  id: string;
  label: string;
  note: string;
  // developerName of the agent bound to this channel, when the binding is
  // resolvable from queryable data (fact, not inference).
  boundAgentDeveloperName?: string;
}

export class AgentChannelExposureCheck implements SecurityCheck {
  readonly id = 'agent-channel-exposure';
  readonly name = 'Agentforce Channel Exposure';
  readonly category = 'AI & Agents';
  readonly description =
    'Correlates active Agentforce agents with the channels that reach them (Experience Cloud sites, embedded deployments, messaging channels) and flags guest-reachable exposure.';

  readonly dependsOnCache = ['agentInventory', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Gate: only meaningful when the inventory was built successfully. Any other
    // state (not-enabled / unknown) means we stay silent — same convention as the
    // other AI & Agents dependent checks.
    if (ctx.cache.agentAccess !== 'ok') return { findings };

    const inventory = ctx.cache.agentInventory ?? [];
    const activeAgents = inventory.filter((a) => a.type === 'agent' && a.isActive);
    if (activeAgents.length === 0) return { findings };

    // Discover channels. Each source is queried defensively: an org may lack any of
    // these objects, and a missing object must never be read as "no exposure" in a
    // way that hides a real surface — but equally we must not invent exposure we
    // cannot support. We simply skip sources that are unavailable.
    const guestSites = await this.queryGuestSites(ctx);
    const messagingChannels = await this.queryMessagingChannels(ctx);
    const embedded = await this.queryEmbeddedDeployments(ctx);

    // Build the set of public (guest-reachable) channels.
    const publicChannels: PublicChannel[] = [];
    for (const n of guestSites) {
      publicChannels.push({
        kind: 'experience-site',
        id: n.Id,
        label: n.Name,
        note: `Live Experience Cloud site with an active guest user (path: ${n.UrlPathPrefix ?? '(default)'})`,
      });
    }
    for (const e of embedded) {
      // A deployment is public when it is bound to a live guest site OR carries no
      // authenticated-site marker. We treat any embedded deployment discovered here
      // as a public web surface (embedded chat is served to the public web).
      const label = e.DeveloperName ?? e.DurableId ?? e.Id ?? 'Embedded deployment';
      const boundAgent = e.AgentDeveloperName ?? e.BotDeveloperName ?? undefined;
      publicChannels.push({
        kind: 'embedded-deployment',
        id: e.Id ?? e.DurableId ?? label,
        label,
        note: e.SiteName ? `Embedded deployment on site "${e.SiteName}"` : 'Embedded service deployment (web-reachable)',
        boundAgentDeveloperName: boundAgent ?? undefined,
      });
    }

    // Resolve agent->channel bindings from Tooling deployment configs where the
    // platform exposes them. This is the only source that lets us assert exposure
    // as fact rather than inference.
    const bindings = await this.queryAgentChannelBindings(ctx);
    // Merge Tooling bindings onto the embedded channels, and record a site-based
    // binding as a public channel when the binding names a guest site.
    const guestSiteIds = new Set(guestSites.map((n) => n.Id));
    for (const b of bindings) {
      if (!b.agentDeveloperName) continue;
      // Attach to any embedded channel with the same deployment developer name.
      const match = publicChannels.find(
        (c) => c.kind === 'embedded-deployment' && c.label === b.deploymentDeveloperName,
      );
      if (match) {
        match.boundAgentDeveloperName = b.agentDeveloperName;
      } else if (b.siteId && guestSiteIds.has(b.siteId)) {
        // Binding points an agent at a guest site directly.
        const site = guestSites.find((n) => n.Id === b.siteId)!;
        publicChannels.push({
          kind: 'experience-site',
          id: `${site.Id}:${b.agentDeveloperName}`,
          label: site.Name,
          note: `Live guest Experience Cloud site "${site.Name}" hosting agent "${b.agentDeveloperName}"`,
          boundAgentDeveloperName: b.agentDeveloperName,
        });
      }
    }

    // Split into channels we could tie to a specific active agent (fact) vs public
    // channels we discovered but could not map to an agent (inference required).
    const activeByDevName = new Map(activeAgents.map((a) => [a.developerName, a]));
    const mappedExposures: Array<{ agent: AgentDefinition; channel: PublicChannel }> = [];
    const unmappedPublicChannels: PublicChannel[] = [];

    for (const c of publicChannels) {
      const boundAgent = c.boundAgentDeveloperName
        ? activeByDevName.get(c.boundAgentDeveloperName)
        : undefined;
      if (boundAgent) {
        mappedExposures.push({ agent: boundAgent, channel: c });
      } else {
        unmappedPublicChannels.push(c);
      }
    }

    // Critical: a specific active agent hosted on a guest-reachable channel. This is
    // asserted only where the agent->channel binding is a fact.
    for (const { agent, channel } of mappedExposures) {
      findings.push({
        id: `agent-channel-exposure-guest-${agent.developerName}-${slug(channel.id)}`,
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `Active agent "${agent.label}" is reachable through a guest/public channel`,
        detail:
          `The Agentforce agent "${agent.label}" (${agent.developerName}) is bound to ${channel.note}. ` +
          `Unauthenticated visitors can send this agent input, so any prompt-injection payload reaches an agent ` +
          `that executes with the data access of its run-as user${agent.runAsUserId ? ` (${agent.runAsUserId})` : ''}. ` +
          `This is the exact combination behind the ForcedLeak pattern: public input channel plus a privileged agent identity.`,
        remediation:
          'Confirm this agent is intended to be publicly reachable. If so, tightly scope the run-as user (least privilege), review the agent action surface for write-capable actions, and ensure Event Monitoring / Transaction Security cover the agent. If not intended, remove the guest/public binding.',
        affectedItems: [
          {
            label: `${agent.label} (${agent.developerName})`,
            url: `${baseUrl}/lightning/setup/SetupNetworks/home`,
            note: channel.note,
          },
        ],
      });
    }

    // Info: agents that are active but not tied to any public channel we found — the
    // internal-only inventory value. Reported once, listing the internal channels.
    const publiclyExposedDevNames = new Set(mappedExposures.map((m) => m.agent.developerName));
    const internalAgents = activeAgents.filter((a) => !publiclyExposedDevNames.has(a.developerName));
    const internalChannels = messagingChannels.filter((m) => m.IsActive !== false);
    if (internalAgents.length > 0 && unmappedPublicChannels.length === 0) {
      findings.push({
        id: 'agent-channel-exposure-internal',
        category: this.category,
        riskLevel: 'INFO',
        title: `${internalAgents.length} active agent(s) on internal-only channels`,
        detail:
          `${internalAgents.length} active agent(s) were not found on any guest-reachable Experience Cloud site or public embedded deployment. ` +
          (internalChannels.length > 0
            ? `${internalChannels.length} messaging channel(s) are configured (internal / authenticated inbound surfaces). `
            : 'No public web channels were discovered. ') +
          `Channel reachability in Salesforce is not always expressed in queryable metadata, so treat this as "no public exposure found" rather than a guarantee.`,
        remediation:
          'Confirm these agents are only exposed on authenticated/internal channels. Re-check after any new Experience Cloud site or embedded deployment goes live.',
        affectedItems: internalAgents.map((a) => ({
          label: `${a.label} (${a.developerName})`,
          note: `active v${a.activeVersion ?? '?'}${a.runAsUserId ? ` | run-as: ${a.runAsUserId}` : ''}`,
        })),
      });
    }

    // Medium (honest inference): we found active agents AND public channels, but could
    // not resolve which agent sits on which channel from queryable data. We state the
    // two lists separately and say the mapping needs manual confirmation. We never
    // claim a specific exposure we cannot support.
    if (unmappedPublicChannels.length > 0) {
      findings.push({
        id: 'agent-channel-exposure-unmapped',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `Public channel(s) and active agent(s) present, but the agent-to-channel mapping could not be confirmed`,
        detail:
          `This org has ${activeAgents.length} active agent(s) and ${unmappedPublicChannels.length} guest-reachable / public channel(s), ` +
          `but the platform did not expose a queryable binding tying a specific agent to a specific channel. ` +
          `Whether any agent is actually reachable from these public channels needs manual confirmation in Setup ` +
          `(Digital Experiences / Embedded Service deployments). The lists below are reported separately and are NOT asserted as a live exposure.`,
        remediation:
          'Manually confirm, for each public channel, whether an agent is deployed on it (Setup → Embedded Service Deployments and each Experience site\'s Agentforce configuration). Where an agent is publicly reachable, scope its run-as user to least privilege and review its action surface.',
        affectedItems: [
          ...activeAgents.map((a) => ({
            label: `Active agent: ${a.label} (${a.developerName})`,
            note: `run-as: ${a.runAsUserId ?? 'unknown'}`,
          })),
          ...unmappedPublicChannels.map((c) => ({
            label: `Public channel: ${c.label}`,
            note: c.note,
          })),
        ],
      });
    }

    return { findings };
  }

  // Live Experience Cloud sites with an active guest user. Defensive: if Network is
  // unavailable, return [] (we then simply cannot assert site exposure).
  private async queryGuestSites(ctx: AuditContext): Promise<NetworkRecord[]> {
    try {
      const rows = await ctx.soql.queryAll<NetworkRecord>(
        `SELECT Id, Name, Status, UrlPathPrefix, GuestUserId
         FROM Network
         WHERE Status = 'Live'`,
      );
      return rows.filter((n) => n.GuestUserId !== null);
    } catch {
      return [];
    }
  }

  private async queryMessagingChannels(ctx: AuditContext): Promise<MessagingChannelRecord[]> {
    try {
      return await ctx.soql.queryAll<MessagingChannelRecord>(
        `SELECT Id, MasterLabel, ChannelType, IsActive FROM MessagingChannel`,
      );
    } catch {
      return [];
    }
  }

  // Embedded Service deployment details (embedded chat / messaging for web). Query the
  // standard object via SOQL; schema varies by release so we tolerate field/object
  // absence and fall back to a minimal projection.
  private async queryEmbeddedDeployments(ctx: AuditContext): Promise<EmbeddedServiceRecord[]> {
    try {
      return await ctx.soql.queryAll<EmbeddedServiceRecord>(
        `SELECT Id, DeveloperName, DurableId, Site, SiteName FROM EmbeddedServiceDetail`,
      );
    } catch {
      try {
        return await ctx.soql.queryAll<EmbeddedServiceRecord>(
          `SELECT DurableId, DeveloperName FROM EmbeddedServiceDetail`,
        );
      } catch {
        return [];
      }
    }
  }

  // Best-effort agent->channel binding from Tooling deployment config. Returns [] if
  // the objects/fields are not queryable in this org/release.
  private async queryAgentChannelBindings(
    ctx: AuditContext,
  ): Promise<Array<{ deploymentDeveloperName?: string; agentDeveloperName?: string; siteId?: string }>> {
    try {
      const rows = await ctx.tooling.query<EmbeddedServiceRecord>(
        `SELECT Id, DeveloperName, Site, AgentDeveloperName FROM EmbeddedServiceConfig`,
      );
      return rows.map((r) => ({
        deploymentDeveloperName: r.DeveloperName ?? undefined,
        agentDeveloperName: r.AgentDeveloperName ?? r.BotDeveloperName ?? undefined,
        siteId: r.Site ?? undefined,
      }));
    } catch {
      return [];
    }
  }
}

function slug(s: string): string {
  return s.replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'x';
}
