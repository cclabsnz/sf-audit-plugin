import { readFileSync } from 'node:fs';
import { Args } from '@oclif/core';
import { Flags, SfCommand } from '@salesforce/sf-plugins-core';
import { explain, ExplainError, parseResult, type Explanation } from '../../report/explain.js';
import type { AuditResult } from '../../findings/AuditResult.js';

export default class AuditExplainCommand extends SfCommand<Explanation> {
  public static summary = 'Explain a check, or one finding from an audit run';
  public static description =
    'With a check id: what the check looks for, its domain, effort, impact and compliance mapping. With --file and a finding id: the finding from that run, what it affects, the attack chains it is part of and the fix-first action that closes it.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> apex-sharing',
    '<%= config.bin %> <%= command.id %> guest-user-sharing-exposure --file ./audit.json',
  ];

  public static args = {
    id: Args.string({ description: 'A check id (sf audit list) or a finding id from a report.', required: true }),
  };

  public static flags = {
    file: Flags.file({
      summary: 'A report from sf audit security --json (full result, not --digest or --summary).',
      exists: true,
    }),
  };

  public async run(): Promise<Explanation> {
    const { args, flags } = await this.parse(AuditExplainCommand);
    let result: AuditResult | undefined;
    if (flags.file) {
      try {
        result = parseResult(readFileSync(flags.file, 'utf8'));
      } catch (err) {
        this.error(`Could not read an audit result from ${flags.file}: ${err instanceof Error ? err.message : String(err)}`, {
          suggestions: ['Pass the output of sf audit security --json, without --digest or --summary.'],
        });
      }
    }
    let out: Explanation;
    try {
      out = explain(args.id as string, result);
    } catch (err) {
      if (err instanceof ExplainError) this.error(err.message, { suggestions: [err.suggestion] });
      throw err;
    }
    this.print(out);
    return out;
  }

  private print(out: Explanation): void {
    const c = out.check;
    this.log(`${c.name} (${c.id})`);
    if (c.domain) this.log(`Domain: ${c.domain}`);
    this.log(c.description);
    if (c.impact) this.log(`\nWhy it matters: ${c.impact}`);
    if (c.effort) this.log(`Typical effort: ${c.effort}`);
    if (c.complianceTags.length > 0) this.log(`Maps to: ${c.complianceTags.join(', ')}`);
    const f = out.finding;
    if (f) {
      this.log(`\n${f.severity} ${f.status}: ${f.title}`);
      this.log(f.detail);
      this.log(`\nFix: ${f.remediation}`);
      if (f.affectedCount > 0) {
        const more = f.affectedCount > f.affectedSample.length ? ` and ${f.affectedCount - f.affectedSample.length} more` : '';
        this.log(`Affects: ${f.affectedSample.join(', ')}${more}`);
      }
      for (const ch of f.chains) this.log(`Part of ${ch.label} ${ch.title} (${ch.severity})${ch.breaksChain ? ': fixing this breaks it' : ''}`);
      if (f.action) this.log(`Fix-first plan: action ${f.action.rank} (${f.action.wave}): ${f.action.title}`);
    }
    if (out.findings) {
      this.log(`\nIn this run:`);
      for (const x of out.findings) this.log(`  ${x.id}  ${x.status === 'open' ? x.severity : x.status}  ${x.title}`);
    }
  }
}

