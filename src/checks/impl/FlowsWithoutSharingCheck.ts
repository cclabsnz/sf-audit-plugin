import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface FlowRecord {
  Id: string;
  MasterLabel: string;
  ProcessType: string;
  Status: string;
  RunInMode: string | null;
}

export class FlowsWithoutSharingCheck implements SecurityCheck {
  readonly id = 'flows-without-sharing';
  readonly name = 'Flows Without Sharing Context';
  readonly category = 'Flow Security';
  readonly description = 'Identifies active flows running in system context without sharing enforcement';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const flows = await ctx.tooling.query<FlowRecord>(
      "SELECT Id, MasterLabel, ProcessType, Status, RunInMode FROM Flow WHERE Status = 'Active'"
    );

    const total = flows.length;

    const autolaunchedWithoutSharing = flows.filter(
      (f) =>
        f.ProcessType === 'AutoLaunchedFlow' &&
        (f.RunInMode === 'DefaultMode' || f.RunInMode === null)
    );

    const screenWithoutSharing = flows.filter(
      (f) =>
        f.ProcessType === 'Flow' &&
        (f.RunInMode === 'DefaultMode' || f.RunInMode === null)
    );

    if (autolaunchedWithoutSharing.length > 0) {
      const count = autolaunchedWithoutSharing.length;
      findings.push({
        id: 'flows-autolaunched-without-sharing',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${count} autolaunched flow(s) run without user sharing context`,
        affectedItems: autolaunchedWithoutSharing.map((f) => ({
          label: f.MasterLabel,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${f.Id}`,
          note: 'Set "Run Flow As" to "User" or document why system context is required',
        })),
        detail:
          "Autolaunched flows running in Default Mode execute with system-level data access, ignoring the triggering user's record visibility.",
        remediation:
          'Set "Run Flow As" to "User" for autolaunched flows that access sensitive data, or explicitly document why system context is required.',
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
          label: f.MasterLabel,
          url: `${baseUrl}/builder_platform_interaction/flowBuilder.app?flowId=${f.Id}`,
          note: 'Review and set "Run Flow As" to "User" where appropriate',
        })),
        detail:
          "Screen flows in Default Mode may allow users to view or modify records they wouldn't normally have access to.",
        remediation:
          'Review each screen flow and set "Run Flow As" to "User" where appropriate to enforce record-level security.',
      });
    }

    if (autolaunchedWithoutSharing.length === 0 && screenWithoutSharing.length === 0) {
      findings.push({
        id: 'flows-without-sharing-none',
        category: this.category,
        riskLevel: 'LOW',
        title: 'No active flows running without sharing context identified',
        detail: `All ${total} active flows either enforce user sharing context or are not autolaunched/screen flow types.`,
        remediation: 'Continue to review flow settings when new flows are activated.',
      });
    }

    return { findings };
  }
}
