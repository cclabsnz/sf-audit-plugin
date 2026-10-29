import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { FlowRepository } from '@cclabsnz/sf-core';

const WITHOUT_SHARING = 'SystemModeWithoutSharing';

export class FlowsWithoutSharingCheck implements SecurityCheck {
  readonly id = 'flows-without-sharing';
  readonly name = 'Flows Without Sharing Context';
  readonly category = 'Flow Security';
  readonly description = 'Identifies active autolaunched and screen flows set to run in system context without sharing';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const flows = await new FlowRepository(ctx.soql, ctx.tooling).listActiveVersions();

    const total = flows.length;

    // Only "System Context Without Sharing—Access All Data" skips sharing by the flow's own setting.
    // Default Mode is not flagged: a screen flow then runs as the user, and an autolaunched flow
    // started by a user runs as that user (from Apex or other automation it inherits the caller's
    // context). Record-, schedule- and platform-event-triggered flows always run in system context
    // without sharing and have no setting to change, so they are out of scope here.
    const withoutSharing = (f: { runInMode: string | null }) => f.runInMode === WITHOUT_SHARING;
    const autolaunchedWithoutSharing = flows.filter((f) => f.processType === 'AutoLaunchedFlow' && withoutSharing(f));
    const screenWithoutSharing = flows.filter((f) => f.processType === 'Flow' && withoutSharing(f));

    if (autolaunchedWithoutSharing.length > 0) {
      const count = autolaunchedWithoutSharing.length;
      findings.push({
        id: 'flows-autolaunched-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} autolaunched flow(s) run without user sharing context`,
        affectedItems: autolaunchedWithoutSharing.map((f) => ({
          label: f.masterLabel,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${f.id}`,
          note: 'Runs in system context without sharing',
        })),
        detail:
          "These autolaunched flows are set to run in system context without sharing, so they read and change records whatever the running user's sharing allows.",
        remediation:
          'Set each flow to System Context With Sharing, which applies the running user\'s record access whoever starts it. Default Mode applies sharing only when a user starts the flow directly; it inherits the context of Apex or automation that calls it. Keep without-sharing only where the flow must reach records its callers cannot see, document why, and check that its inputs cannot choose which records it touches.',
      });
    }

    if (screenWithoutSharing.length > 0) {
      const count = screenWithoutSharing.length;
      findings.push({
        id: 'flows-screen-without-sharing',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${count} screen flow(s) run without user sharing context`,
        affectedItems: screenWithoutSharing.map((f) => ({
          label: f.masterLabel,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${f.id}`,
          note: 'Runs in system context without sharing',
        })),
        detail:
          "These screen flows are set to run in system context without sharing, so whoever can run them may view or change records their own sharing would not show them.",
        remediation:
          'Set each screen flow to run in Default Mode (user context) or system context with sharing, unless it must reach records its users cannot see; for those, check that no screen input chooses which records it reads or changes.',
      });
    }

    if (autolaunchedWithoutSharing.length === 0 && screenWithoutSharing.length === 0) {
      findings.push({
        id: 'flows-without-sharing-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active flows running without sharing context identified',
        detail: `None of the ${total} active autolaunched or screen flows is set to run in system context without sharing.`,
        remediation: 'Continue to review flow settings when new flows are activated.',
      });
    }

    return { findings };
  }
}
