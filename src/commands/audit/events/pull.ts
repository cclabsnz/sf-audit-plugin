// src/commands/audit/events/pull.ts
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { buildAuditContext, resolveOrgInfo } from '../../../lib/wire.js';
import { EventBaselineStore } from '../../../events/EventBaselineStore.js';
import { pullEventLogs, type EventsPullResult } from '../../../events/pullEventLogs.js';
import { sanitizeTypes } from '../../../events/eventLogQuery.js';
import type { EventLogAccess } from '../../../context/AuditCache.js';

export default class AuditEventsPullCommand extends SfCommand<EventsPullResult> {
  public static summary = 'Capture free EventLogFile daily logs to local disk';
  public static description =
    'Downloads the org\'s free (Daily-interval) EventLogFile CSV logs to ~/.sf/event-baseline/{orgId} so they ' +
    'survive the free tier\'s ~1-day retention window. Read-only (GET only). Idempotent: rows already saved are ' +
    'skipped, so it is safe to run daily via cron or a scheduled GitHub Action to build a rolling local baseline ' +
    'of login, API, and error activity without the paid Event Monitoring / Shield add-on.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --since 3',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --types Login,ApiTotalUsage',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --output ./event-baseline',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    since: Flags.integer({
      summary: 'Number of days of LogDate to request (LAST_N_DAYS window).',
      default: 1,
      helpValue: '1',
    }),
    types: Flags.string({
      summary: 'Restrict to specific EventTypes (comma-separated). Omit to pull every available type.',
      helpValue: 'Login,ApiTotalUsage',
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Base directory to store logs under. Defaults to ~/.sf/event-baseline.',
      helpValue: './event-baseline',
    }),
  };

  public async run(): Promise<EventsPullResult> {
    const { flags } = await this.parse(AuditEventsPullCommand);

    const conn = flags['target-org'].getConnection('62.0') as any;
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, orgInfo);

    const store = new EventBaselineStore(flags.output);
    const types = sanitizeTypes(flags.types);

    this.log(`Pulling free EventLogFile logs for org: ${orgInfo.name} (${orgInfo.id})`);
    if (types.length > 0) this.log(`Restricting to event type(s): ${types.join(', ')}`);

    const result = await pullEventLogs(
      { soql: ctx.soql, rest: ctx.rest, store, orgId: orgInfo.id },
      { since: flags.since, types, warn: (msg) => this.warn(msg) },
    );

    if (result.accessError) {
      this.warn(this.accessMessage(result.accessError));
      return result;
    }

    if (result.found === 0) {
      this.log(
        `No EventLogFile records found for the last ${flags.since} day(s). Free daily logs need ` +
          'Enterprise/Unlimited/Performance edition and appear ~24h after the activity.',
      );
      return result;
    }

    this.printSummary(result);
    return result;
  }

  private accessMessage(access: EventLogAccess): string {
    switch (access) {
      case 'no-permission':
        return (
          'EventLogFile is not readable by this org user: the "View Event Log Files" permission is missing. ' +
          'Grant it to the running user and re-run.'
        );
      case 'not-enabled':
        return (
          'EventLogFile is not available on this org/edition. Free daily logs require Enterprise/Unlimited/' +
          'Performance edition (Developer Edition also exposes them); other editions need the Event Monitoring add-on.'
        );
      default:
        return 'EventLogFile could not be queried. Verify the org connection and that EventLogFile is accessible.';
    }
  }

  private printSummary(result: EventsPullResult): void {
    this.log('');
    this.log('─────────────────────────────');
    this.log('  Event Baseline Pull');
    this.log('─────────────────────────────');
    this.log(`  Found        ${String(result.found).padStart(4)}`);
    this.log(`  Downloaded   ${String(result.downloaded).padStart(4)}`);
    this.log(`  Skipped      ${String(result.skipped).padStart(4)}  (already saved)`);
    if (result.failed > 0) this.log(`  Failed       ${String(result.failed).padStart(4)}`);
    this.log(`  Total bytes  ${String(result.totalBytes).padStart(4)}`);
    this.log('─────────────────────────────');
    this.log(`  Saved to: ${result.storagePath}`);
    if (result.manifestPath) this.log(`  Manifest: ${result.manifestPath}`);
  }
}
