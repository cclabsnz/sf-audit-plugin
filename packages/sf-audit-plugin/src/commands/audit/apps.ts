import { readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { resolveOrgInfo, buildAuditContext } from '../../lib/wire.js';
import { analyzeApps } from '../../apps/analyzeApps.js';
import { renderJson, renderMarkdown, renderTable } from '../../apps/renderApps.js';
import type { AppFinding } from '../../apps/types.js';

export default class AuditAppsCommand extends SfCommand<AppFinding[]> {
  public static summary = 'Report connected apps that are granted more access than they use';
  public static description =
    'Reads the RestApi EventLogFile to see which objects each connected app actually touches, compares that ' +
    'against the access its run-as user is granted, and reports the over-grant per object and read/write bit, ' +
    'plus a suggested least-privilege permission set. Read-only. "Used" is a lower bound (RestApi attributes ' +
    'roughly half of API traffic), so revoke recommendations are suppressed below a soak window.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg --since 7',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --from ~/.sf/event-baseline/00Dxxx',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --format json',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    since: Flags.integer({ summary: 'Days of RestApi log to analyze.', default: 7, helpValue: '7' }),
    from: Flags.string({ summary: 'Read RestApi CSVs from a local events-pull baseline dir instead of downloading.', helpValue: './baseline' }),
    soak: Flags.integer({ summary: 'Minimum window (days) before asserting revoke recommendations.', default: 7 }),
    format: Flags.string({ summary: 'Output format.', options: ['table', 'json', 'md'], default: 'table' }),
  };

  public async run(): Promise<AppFinding[]> {
    const { flags } = await this.parse(AuditAppsCommand);
    const conn = flags['target-org'].getConnection('62.0') as any;
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, orgInfo);

    let restApiCsv = '';
    if (flags.from) {
      // Concatenate any RestApi CSVs found under the baseline dir.
      const dir = join(flags.from, 'RestApi');
      try {
        restApiCsv = readdirSync(dir).filter((f) => f.endsWith('.csv')).map((f) => readFileSync(join(dir, f), 'utf-8')).join('\n');
      } catch {
        this.error(`No RestApi logs under ${dir}. Run "sf audit events pull" first, or drop --from to download.`);
      }
    } else {
      const rows = await ctx.soql.queryAll<{ Id: string }>(
        `SELECT Id FROM EventLogFile WHERE EventType = 'RestApi' AND LogDate = LAST_N_DAYS:${flags.since} ORDER BY LogDate DESC`,
      );
      for (const r of rows) {
        // Stream each RestApi log to a temp file and read it back (getRawToFile never buffers the body).
        const tmp = join(process.env.TMPDIR ?? '/tmp', `sfaudit-restapi-${r.Id}.csv`);
        await ctx.rest.getRawToFile(`/sobjects/EventLogFile/${r.Id}/LogFile`, tmp);
        try {
          restApiCsv += '\n' + readFileSync(tmp, 'utf-8');
        } finally {
          try { unlinkSync(tmp); } catch { /* ignore if already gone */ }
        }
      }
    }

    const findings = await analyzeApps(restApiCsv, ctx.soql, { since: flags.since, soakDays: flags.soak });
    const out = flags.format === 'json' ? renderJson(findings) : flags.format === 'md' ? renderMarkdown(findings) : renderTable(findings);
    this.log(out);
    return findings;
  }
}
