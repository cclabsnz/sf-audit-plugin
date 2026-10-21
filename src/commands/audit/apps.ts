import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { resolveOrgInfo, buildAuditContext } from '../../lib/wire.js';
import { analyzeApps } from '../../apps/analyzeApps.js';
import { renderJson, renderMarkdown, renderTable } from '../../apps/renderApps.js';
import { emitPermissionSets } from '../../apps/permissionSetGenerator.js';
import { ApiLogListingError, assessLogCoverage, downloadApiLogs, type ApiLogs } from '../../apps/apiLogSource.js';
import type { AppFinding } from '../../apps/types.js';

export default class AuditAppsCommand extends SfCommand<AppFinding[]> {
  public static summary = 'Report connected apps that are granted more access than they use';
  public static description =
    'Reads the RestApi, BulkApi2, and GraphQL EventLogFiles to see which objects each connected app actually touches, ' +
    'compares that against the access its run-as user is granted, and reports the over-grant per object and read/write bit, ' +
    'plus a suggested least-privilege permission set. Read-only. "Used" is a lower bound, so revoke recommendations ' +
    'are suppressed below a soak window.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg --since 7',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --from ~/.sf/event-baseline/00Dxxx',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --emit-permset ./force-app/main/default/permissionsets',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --format json',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    since: Flags.integer({ summary: 'Days of API logs to analyze.', default: 7, min: 1, helpValue: '7' }),
    from: Flags.string({ summary: 'Read API CSVs from a local events-pull baseline dir instead of downloading.', helpValue: './baseline' }),
    soak: Flags.integer({ summary: 'Minimum window (days) before asserting revoke recommendations.', default: 7, min: 0 }),
    format: Flags.string({ summary: 'Output format.', options: ['table', 'json', 'md'], default: 'table' }),
    'emit-permset': Flags.string({
      summary: 'Write a least-privilege .permissionset-meta.xml per app into this local directory. Nothing is deployed.',
      helpValue: './permissionsets',
    }),
  };

  public async run(): Promise<AppFinding[]> {
    const { flags } = await this.parse(AuditAppsCommand);
    // No pinned version: the org's own API version, so fields and objects added since an
    // older release are visible. A pin at 62.0 hid every newer permission field.
    const conn = flags['target-org'].getConnection() as any;
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, orgInfo);

    let restApiCsv = '';
    let bulkApi2Csv = '';
    let graphQlCsv = '';
    let auraCsv = '';
    let incompleteUsage: string | undefined;

    if (flags.from) {
      const readDirCsvs = (subDir: string): string => {
        const d = join(flags.from!, subDir);
        let names: string[];
        try {
          names = readdirSync(d);
        } catch (e) {
          // A missing log-type folder just means that type was not pulled; anything else must surface.
          if ((e as NodeJS.ErrnoException).code === 'ENOENT') return '';
          throw e;
        }
        return names
          .filter((f) => f.endsWith('.csv'))
          .map((f) => readFileSync(join(d, f), 'utf-8'))
          .join('\n');
      };

      restApiCsv = readDirCsvs('RestApi');
      bulkApi2Csv = readDirCsvs('BulkApi2');
      graphQlCsv = readDirCsvs('GraphQlQueryExecution');
      auraCsv = readDirCsvs('AuraRequest');

      if (!restApiCsv && !bulkApi2Csv && !graphQlCsv && !auraCsv) {
        this.error(`No API logs under ${flags.from}. Run "sf audit events pull" first, or drop --from to download.`);
      }
    } else {
      let logs: ApiLogs;
      try {
        logs = await downloadApiLogs(ctx, flags.since);
      } catch (e) {
        // An unreadable EventLogFile must not become an empty, clean-looking report.
        if (e instanceof ApiLogListingError) this.error(e.message);
        throw e;
      }
      const coverage = assessLogCoverage(logs, flags.since);
      if (coverage.fatal) this.error(coverage.fatal);
      if (coverage.empty) this.warn(coverage.empty);
      if (coverage.incomplete) {
        incompleteUsage = coverage.incomplete;
        this.warn(`${incompleteUsage}; usage is incomplete and revoke recommendations are suppressed. First error: ${logs.failed[0].error}`);
      }
      restApiCsv = logs.csv.RestApi;
      bulkApi2Csv = logs.csv.BulkApi2;
      graphQlCsv = logs.csv.GraphQlQueryExecution;
      auraCsv = logs.csv.AuraRequest;
    }

    const findings = await analyzeApps(restApiCsv, ctx.soql, {
      since: flags.since,
      soakDays: flags.soak,
      bulkApi2Csv,
      graphQlCsv,
      auraCsv,
      incompleteUsage,
    });

    if (flags['emit-permset']) {
      // Local files only: nothing is deployed to the org.
      const { written, skipped } = emitPermissionSets(findings, flags['emit-permset']);
      this.log(`Emitted ${written.length} permission set file(s) into ${flags['emit-permset']}`);
      if (skipped.length > 0) {
        this.warn(
          `Skipped ${skipped.length} app(s) whose recommendation is not asserted (soak window, many interactive users, or incomplete logs): ` +
            skipped.join(', '),
        );
      }
    }

    const out = flags.format === 'json' ? renderJson(findings) : flags.format === 'md' ? renderMarkdown(findings) : renderTable(findings);
    // JSON carries the same flag in every finding's notes; the human formats get it as a header line.
    if (incompleteUsage && flags.format !== 'json') this.log(`INCOMPLETE: ${incompleteUsage}. "Used" undercounts; revoke recommendations suppressed.`);
    this.log(out);
    return findings;
  }
}
