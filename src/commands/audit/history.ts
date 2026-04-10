// src/commands/audit/history.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { HistoryStore } from '../../history/HistoryStore.js';
import { HistoryRenderer } from '../../renderers/HistoryRenderer.js';
import type { AuditResult } from '../../findings/AuditResult.js';

export default class AuditHistoryCommand extends SfCommand<AuditResult[]> {
  public static summary = 'Show audit history for an org';
  public static description =
    'Scans archived audit reports for the target org, prints a terminal table, and writes an HTML timeline.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --reports-dir ./reports --limit 10',
  ];

  public static flags = {
    'target-org':   Flags.requiredOrg(),
    'reports-dir':  Flags.string({
      summary: 'Directory containing archived report files. Defaults to ~/.sf/audit-history/{orgId}.',
      helpValue: './reports',
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the HTML timeline. Defaults to current directory.',
      default: '.',
    }),
    limit: Flags.integer({
      summary: 'Maximum number of most-recent runs to include.',
      helpValue: '20',
    }),
  };

  public async run(): Promise<AuditResult[]> {
    const { flags } = await this.parse(AuditHistoryCommand);

    const orgId    = flags['target-org'].getOrgId();
    const store    = new HistoryStore();
    const reportsDir = flags['reports-dir'];

    let results = store.list(orgId, reportsDir);

    if (results.length < 2) {
      if (results.length === 0) {
        this.log(`No audit history found for org ${orgId}.`);
        this.log(`Run 'sf audit security --target-org <alias>' to create the first report.`);
      } else {
        this.log(`Only 1 audit run found for org ${orgId}. Run at least 2 audits to see trends.`);
      }
      return results;
    }

    if (flags.limit !== undefined) {
      results = results.slice(-flags.limit);
    }

    const renderer = new HistoryRenderer();
    this.log(renderer.renderTable(results));

    const filename   = `sf-audit-history-${orgId}-${Date.now()}.html`;
    const outputPath = path.join(flags.output, filename);
    fs.writeFileSync(outputPath, renderer.renderHtml(results), 'utf-8');
    this.log(`\nHistory report written: ${outputPath}`);

    return results;
  }
}
