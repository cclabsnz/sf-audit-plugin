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

// Messaging channels. Used for inventory (info) findings only — we never assert an
// agent is reachable on one, because no queryable binding ties an agent to a channel.
//
// Do NOT describe these as internal or authenticated. `MessagingChannel` is not just
// SMS/WhatsApp/Facebook: creating a "Messaging for In-App and Web" channel (Setup →
// Messaging Settings → New Channel) also creates a MessagingChannel record, and that
// one is a public web surface reachable through the messaging API's unauthenticated
// guest access-token flow. ChannelType would distinguish them, but the literal picklist
// values are not confirmed here, so this check reports the count as "type not
// determined" rather than classifying reach it has not established.
interface MessagingChannelRecord {
  Id: string;
  MasterLabel: string | null;
  // The field is MessageType, NOT ChannelType — there is no ChannelType field on
  // MessagingChannel. Selecting one fails with INVALID_FIELD, and because the query is
  // wrapped in a catch that returns [], that failure is silent: every channel disappears.
  MessageType?: string | null;
  PlatformType?: string | null;
  IsActive?: boolean | null;
}

// MessageType values that are reachable from a browser, and therefore candidate public
// surfaces. Verified against a live org's MessagingChannel describe (2026-08); the full
// picklist also covers Text, Phone, WhatsApp, Facebook, Line, WeChat, AppleBusinessChat,
// Rcs, Email, Voice/PstnVoice/SipVoice/WhatsAppVoice, Alexa, GoogleHome, Custom, Omega,
// InternalCopilot, MsCopilot and VoiceIntegrationPilot, none of which is a web endpoint.
const WEB_MESSAGE_TYPES = new Set(['EmbeddedMessaging', 'WebChat']);

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
  kind: 'experience-site' | 'embedded-deployment' | 'messaging-channel-web';
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

    // A web-type messaging channel is a browser-reachable surface: Embedded Messaging and
    // Chat are served to the public web and, for guests, reached through the messaging API's
    // unauthenticated access-token flow. Treat those as public channel candidates. We still
    // cannot bind an agent to one (no queryable binding exists), so they land in the unmapped
    // list and are reported as an unconfirmed mapping, never as an asserted exposure.
    for (const m of messagingChannels) {
      if (m.IsActive === false) continue;
      if (!m.MessageType || !WEB_MESSAGE_TYPES.has(m.MessageType)) continue;
      publicChannels.push({
        kind: 'messaging-channel-web',
        id: m.Id,
        label: m.MasterLabel ?? m.Id,
        note:
          `Messaging channel of type ${m.MessageType}` +
          `${m.PlatformType ? ` (${m.PlatformType})` : ''} — a web-reachable surface, ` +
          `available to unauthenticated visitors via the messaging API's guest access-token flow`,
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
          `Reachability does not depend on the site's Aura endpoint: conversations go to the org's messaging host ` +
          `(<subdomain>.my.salesforce-scrt.com) via the Messaging for In-App and Web API, whose unauthenticated ` +
          `access-token flow needs only the org id and this deployment's API name (the esDeveloperName), both of ` +
          `which are present in the client-side bootstrap of any page that hosts the widget. ` +
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
    // Web-type channels have already been promoted to publicChannels above, so anything left
    // here is a non-web inbound surface (SMS, WhatsApp, Facebook, voice, email, ...).
    const nonWebChannels = messagingChannels.filter(
      (m) => m.IsActive !== false && !(m.MessageType && WEB_MESSAGE_TYPES.has(m.MessageType)),
    );
    if (internalAgents.length > 0 && unmappedPublicChannels.length === 0) {
      const types = [...new Set(nonWebChannels.map((m) => m.MessageType).filter(Boolean))];
      findings.push({
        id: 'agent-channel-exposure-internal',
        category: this.category,
        riskLevel: 'INFO',
        title: `${internalAgents.length} active agent(s) with no public channel binding confirmed`,
        detail:
          `${internalAgents.length} active agent(s) were not found on any guest-reachable Experience Cloud site, public embedded deployment, or web-type messaging channel. ` +
          (nonWebChannels.length > 0
            ? `${nonWebChannels.length} non-web messaging channel(s) are active${types.length > 0 ? ` (${types.join(', ')})` : ''}. ` +
              `These are inbound surfaces whose senders are external parties identified by phone number or account handle — not ` +
              `Salesforce-authenticated users — but they are not browser-reachable endpoints, and no queryable binding ties an ` +
              `agent to a messaging channel, so no exposure is asserted for them either way. `
            : 'No web-reachable channels were discovered. ') +
          `Channel reachability in Salesforce is not always expressed in queryable metadata, so treat this as "no public exposure found" rather than a guarantee, and not as evidence that these agents are internal-only.`,
        remediation:
          'Confirm in Setup → Messaging Settings whether any of these agents is deployed on a messaging channel. Any channel of type EmbeddedMessaging or WebChat is a public web surface and is reported separately; for the remaining channels, verify who can send to them and scope each agent\'s run-as user to least privilege regardless. Re-check after any new Experience Cloud site, embedded deployment, or messaging channel goes live.',
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
        `SELECT Id, MasterLabel, MessageType, PlatformType, IsActive FROM MessagingChannel`,
      );
    } catch {
      // Fall back to the minimal projection so an org missing the type fields still yields an
      // inventory count, rather than reporting no channels at all.
      try {
        return await ctx.soql.queryAll<MessagingChannelRecord>(
          `SELECT Id, MasterLabel, IsActive FROM MessagingChannel`,
        );
      } catch {
        return [];
      }
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
