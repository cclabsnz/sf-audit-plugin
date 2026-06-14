// src/commands/audit/diff.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Args } from '@oclif/core';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { HistoryStore } from '../../history/HistoryStore.js';
import { computeDiff } from '../../history/DiffEngine.js';
import { DiffHtmlRenderer } from '../../renderers/DiffHtmlRenderer.js';
import { DiffJsonRenderer } from '../../renderers/DiffJsonRenderer.js';
import type { DiffRenderer } from '../../renderers/DiffRenderer.js';
import type { AuditDiff } from '../../history/AuditDiff.js';

const DIFF_RENDERERS: Record<string, DiffRenderer> = {
  html: new DiffHtmlRenderer(),
  json: new DiffJsonRenderer(),
};

export default class AuditDiffCommand extends SfCommand<AuditDiff> {
  public static summary = 'Compare two audit report JSON files and show what changed';
  public static description =
    'Loads two audit report JSON files, computes the diff, and writes HTML and/or JSON diff reports.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> baseline.json current.json',
    '<%= config.bin %> <%= command.id %> baseline.json current.json --output ./reports --format html',
  ];

  public static args = {
    baseline: Args.string({ required: true, description: 'Path to the baseline (older) audit JSON report' }),
    current:  Args.string({ required: true, description: 'Path to the current (newer) audit JSON report' }),
  };

  public static flags = {
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write diff reports. Defaults to current directory.',
      default: '.',
    }),
    format: Flags.string({
      char: 'f',
      summary: 'Output format(s), comma-separated: html, json',
      default: 'html,json',
    }),
  };

  public async run(): Promise<AuditDiff> {
    const { args, flags } = await this.parse(AuditDiffCommand);

    const store    = new HistoryStore();
    const baseline = store.load(args['baseline'] as string);
    const current  = store.load(args['current'] as string);

    if (baseline.orgId !== current.orgId) {
      this.warn(`Org IDs differ: baseline=${baseline.orgId}, current=${current.orgId}. Continuing anyway.`);
    }

    const diff    = computeDiff(baseline, current);
    const formats = flags.format.split(',').map((f) => f.trim());
    const baseTs  = baseline.generatedAt.getTime();
    const curTs   = current.generatedAt.getTime();

    fs.mkdirSync(flags.output, { recursive: true });
    for (const format of formats) {
      const renderer = DIFF_RENDERERS[format];
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, json`);
        continue;
      }
      const filename   = `sf-audit-diff-${baseline.orgId}-${baseTs}-vs-${curTs}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, renderer.render(diff), 'utf-8');
      this.log(`Diff report written: ${outputPath}`);
    }

    const scoreDeltaStr  = diff.scoreDelta >= 0 ? `+${diff.scoreDelta}` : `${diff.scoreDelta}`;
    const newCount       = diff.findingChanges.filter((c) => c.type === 'new').length;
    const resolvedCount  = diff.findingChanges.filter((c) => c.type === 'resolved').length;
    this.log('');
    this.log('─────────────────────────────');
    this.log('  Diff Summary');
    this.log('─────────────────────────────');
    this.log(`  Score delta  ${scoreDeltaStr.padStart(6)}`);
    this.log(`  Grade        ${diff.gradeDelta}`);
    this.log(`  New          ${String(newCount).padStart(6)}`);
    this.log(`  Resolved     ${String(resolvedCount).padStart(6)}`);
    this.log('─────────────────────────────');

    return diff;
  }
}
