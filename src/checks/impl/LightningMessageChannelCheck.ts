import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { Finding } from '../../findings/Finding.js';

interface MessageChannelRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel?: string;
  NamespacePrefix?: string | null;
  /** 'unmanaged' and 'unpackaged' are local; 'installed' came from a managed package. */
  ManageableState?: string | null;
  IsExposed: boolean;
}

/** ManageableState values that mean the channel was defined in this org rather than installed. */
const LOCAL_STATES = new Set(['unmanaged', 'unpackaged', 'deprecatedEditable', 'released']);

export class LightningMessageChannelCheck implements SecurityCheck {
  readonly id       = 'lightning-message-channel';
  readonly name     = 'Lightning Message Channel Exposure';
  readonly category = 'Code Security';
  readonly description =
    'Finds Lightning Message Channels published to every namespace, where any component sharing the page can read or write the bus.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const channels = await ctx.tooling.query<MessageChannelRecord>(
      'SELECT Id, DeveloperName, MasterLabel, NamespacePrefix, ManageableState, IsExposed ' +
      'FROM LightningMessageChannel',
    );

    if (channels.length === 0) {
      return {
        findings: [{
          id: 'lightning-message-channel-none',
          category: this.category,
          riskLevel: 'INFO',
          passed: true,
          title: 'No Lightning Message Channels defined',
          detail:
            'This org defines no Lightning Message Channels, so there is no cross-component message bus to expose.',
          remediation: 'No action required.',
        }],
      };
    }

    const exposed = channels.filter((c) => c.IsExposed);

    if (exposed.length === 0) {
      return {
        findings: [{
          id: 'lightning-message-channel-ok',
          category: this.category,
          riskLevel: 'INFO',
          passed: true,
          title: `All ${channels.length} Lightning Message Channel(s) are scoped to their own namespace`,
          detail:
            `None of the ${channels.length} channel(s) set isExposed, so each is usable only by components in the namespace that defines it.`,
          remediation: 'No action required.',
        }],
      };
    }

    // Split by who can actually fix it. isExposed cannot be set back to false, so for an installed
    // channel there is no remediation available inside this org at all.
    const local = exposed.filter((c) => LOCAL_STATES.has(c.ManageableState ?? 'unmanaged'));
    const installed = exposed.filter((c) => !LOCAL_STATES.has(c.ManageableState ?? 'unmanaged'));

    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/LightningMessageChannels/home`;
    const label = (c: MessageChannelRecord): string =>
      `${c.NamespacePrefix ? `${c.NamespacePrefix}__` : ''}${c.DeveloperName}`;

    if (local.length > 0) {
      findings.push({
        id: 'lightning-message-channel-exposed',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${local.length} Lightning Message Channel(s) are exposed to every namespace`,
        detail:
          `${local.length} of ${channels.length} channel(s) set isExposed=true. Lightning Message Service is secure by default: ` +
          'per Salesforce, components in other namespaces cannot read a channel unless isExposed is true, and exposing it lets ' +
          'outside packages publish to and subscribe on it. This single boolean is therefore the whole of what separates the ' +
          'channel from code the org did not write. ' +
          'Who can take advantage is narrower than it first appears, and worth being precise about: subscribing requires importing ' +
          'the channel into a deployed component, so the actor is an installed managed package or anything else deployed into this ' +
          'org — not arbitrary script running on the page. That makes this a design exposure rather than a demonstrated leak. ' +
          'What it costs, where a channel carries record data, is that a message is a plain JavaScript object the publisher ' +
          'assembled. There is no record-level enforcement on a message, so a subscriber reads whatever was placed on the channel ' +
          'irrespective of what its own user is entitled to see, and a publisher can equally put a payload on the channel that a ' +
          'subscriber then treats as trusted input. ' +
          'Note that Visualforce supports only channels where isExposed is true, so a channel used from a Visualforce page is ' +
          'exposed because the platform requires it, not because anyone chose it. ' +
          'This check reads channel metadata only. It establishes that the door is open, not that anything sensitive passes ' +
          'through it: what each channel actually carries is visible only in the publishing component.',
        remediation:
          'Start by reading the publishing component to see what each channel carries, because that decides whether this is urgent ' +
          'or merely untidy: a channel passing a record id is a much smaller problem than one passing field values, and nothing in ' +
          'the metadata distinguishes them. Then check whether any installed package would be positioned to subscribe, since a ' +
          'channel exposed in an org with no third-party components on those pages has no audience today, though it will if one is ' +
          'installed later. ' +
          'If it needs closing, treat it as a design change rather than a setting change: isExposed cannot be set back to false ' +
          'once true, so closing a channel means defining a replacement with isExposed=false and migrating every publisher and ' +
          'subscriber to it. Make every subscriber validate the payload rather than trusting it, since the publisher cannot be ' +
          'authenticated. Where the channel exists only to support a Visualforce page, moving that page to a Lightning Web ' +
          'Component removes the constraint that forced the exposure.',
        affectedItems: local.map((c) => ({
          label: label(c),
          note: c.MasterLabel && c.MasterLabel !== c.DeveloperName ? c.MasterLabel : undefined,
          url: setupUrl,
        })),
      });
    }

    if (installed.length > 0) {
      findings.push({
        id: 'lightning-message-channel-exposed-installed',
        category: this.category,
        riskLevel: 'LOW',
        title: `${installed.length} exposed Lightning Message Channel(s) came from an installed package`,
        detail:
          `${installed.length} exposed channel(s) are owned by an installed package, so they cannot be changed in this org and ` +
          'the exposure is the publisher\'s decision rather than yours. They are listed separately because the reach is the same ' +
          'as a local exposed channel — any component in any namespace can read and write them — while the remediation is not ' +
          'available to you. Worth knowing because Salesforce\'s own AppExchange Security Review requires isExposed=false, so an ' +
          'installed package shipping an exposed channel is a reasonable question to put to the vendor.',
        remediation:
          'Raise it with the package publisher, citing the AppExchange Security Review requirement that isExposed be false. ' +
          'In the meantime, treat any page hosting the package\'s components as a shared bus and avoid placing components that ' +
          'publish sensitive payloads on the same page.',
        affectedItems: installed.map((c) => ({
          label: label(c),
          note: c.ManageableState ?? undefined,
          url: setupUrl,
        })),
      });
    }

    return { findings };
  }
}
