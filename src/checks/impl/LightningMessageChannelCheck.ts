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
          `${local.length} of ${channels.length} channel(s) set isExposed=true, which publishes them to components in any namespace, ` +
          'including every installed managed package. Lightning Message Service is a browser-side bus with no server mediation: ' +
          'any component sharing a page with a publisher or subscriber can subscribe to read every payload, or publish a payload ' +
          'of its own. Sharing rules, org-wide defaults and field-level security govern records and do not apply here, so whatever ' +
          'the channel carries is readable regardless of what the reader is entitled to see. The matching risk is that a subscriber ' +
          'treats the payload as trusted input — taking a record id from a message and passing it to Apex, or rendering it into the ' +
          'page — because the bus looks like a trust boundary and is not one. ' +
          'Note that Visualforce supports only channels where isExposed is true, so a channel used from a Visualforce page is ' +
          'exposed because the platform requires it, not because anyone chose it.',
        remediation:
          'Treat this as a design change rather than a setting change: isExposed cannot be set back to false once true, so closing ' +
          'a channel means defining a replacement with isExposed=false and migrating every publisher and subscriber to it. ' +
          'Before doing that, check what each channel actually carries — a channel passing a record id is a smaller problem than ' +
          'one passing field values — and make every subscriber validate the payload rather than trusting it, since the publisher ' +
          'cannot be authenticated. Where the channel exists only to support a Visualforce page, moving that page to a Lightning ' +
          'Web Component removes the constraint that forced the exposure.',
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
