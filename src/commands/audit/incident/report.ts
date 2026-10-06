import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { resolveBranding, type Branding, type BrandingOverrides } from '@cclabsnz/sf-core';
import { analyseBundle } from '../../../incident/analyse/index.js';
import { BundleIncompleteError, BundleIntegrityError } from '../../../incident/bundleIo.js';
import { buildEvidence, writeEvidence } from '../../../incident/render/evidence.js';
import { redactResult } from '../../../incident/render/redact.js';
import { renderMarkdown } from '../../../incident/render/markdown.js';
import { renderHtml } from '../../../incident/render/html.js';

export interface IncidentReportResult { written: string[] }

export function parseFormats(input: string): string[] {
  const formats = input.split(',').map((f) => f.trim()).filter((f) => f.length > 0);
  const bad = formats.filter((f) => !['html', 'md', 'json'].includes(f));
  if (formats.length === 0 || bad.length > 0) {
    throw new Error(`Unknown --format value(s): ${bad.length > 0 ? bad.join(', ') : input || '(empty)'}. Use html, md, json.`);
  }
  return formats;
}

export async function writeReport(bundleDir: string, opts: { formats: string[]; outputDir: string; redact: boolean; spikeRatio: number; branding: Branding }): Promise<string[]> {
  let result = await analyseBundle(bundleDir, { spikeRatio: opts.spikeRatio });
  if (opts.redact) result = redactResult(result);
  const ev = buildEvidence(result);
  fs.mkdirSync(opts.outputDir, { recursive: true });
  const written: string[] = [];
  const put = (name: string, body: string) => { const p = path.join(opts.outputDir, name); fs.writeFileSync(p, body); written.push(p); };
  if (opts.formats.includes('html')) put('incident-report.html', renderHtml(result, ev, opts.branding));
  if (opts.formats.includes('md')) put('incident-report.md', renderMarkdown(result, ev));
  if (opts.formats.includes('json')) put('incident-report.json', JSON.stringify(result, null, 2));
  written.push(...writeEvidence(opts.outputDir, ev.tables));
  return written;
}

export default class AuditIncidentReportCommand extends SfCommand<IncidentReportResult> {
  public static summary = 'Analyse an incident bundle offline and write a client-facing report';
  public static description =
    'Reads a bundle from `sf audit incident collect` without connecting to the org. Writes an HTML report (print to PDF), ' +
    'Markdown, JSON and one evidence CSV per table. Every number in the report cites an evidence file.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --bundle ~/.sf/incidents/00Dxx0000000000EAA/2026-10-05T00-00-00Z',
    '<%= config.bin %> <%= command.id %> --bundle ./bundle --redact --branding ./report-branding.json',
  ];
  public static flags = {
    bundle: Flags.string({ summary: 'Bundle directory written by incident collect.', required: true }),
    format: Flags.string({ summary: 'Comma-separated: html,md,json.', default: 'html,md,json' }),
    output: Flags.string({ char: 'o', summary: 'Directory to write the report into.', default: '.' }),
    redact: Flags.boolean({ summary: 'Replace linked users with ids and truncate IPs to /24 for wider sharing.', default: false }),
    'spike-ratio': Flags.integer({ summary: 'A day is a spike when controller calls reach this multiple of the baseline median.', default: 5, min: 1 }),
    branding: Flags.string({ summary: 'Path to a report-branding.json.', helpValue: './report-branding.json' }),
    'prepared-for': Flags.string({ summary: 'Client name shown on the report.' }),
  };

  public async run(): Promise<IncidentReportResult> {
    const { flags } = await this.parse(AuditIncidentReportCommand);
    let formats: string[];
    try { formats = parseFormats(flags.format); } catch (e) { this.error((e as Error).message, { exit: 2 }); }
    let overrides: BrandingOverrides | undefined;
    if (flags.branding) overrides = JSON.parse(fs.readFileSync(flags.branding, 'utf-8')) as BrandingOverrides;
    try {
      const written = await writeReport(flags.bundle, {
        formats,
        outputDir: flags.output,
        redact: flags.redact,
        spikeRatio: flags['spike-ratio'],
        branding: resolveBranding(overrides, flags['prepared-for']),
      });
      for (const p of written.filter((x) => !x.endsWith('.csv'))) this.log(`Wrote ${p}`);
      this.log(`Wrote ${written.filter((x) => x.endsWith('.csv')).length} evidence file(s) to ${path.join(flags.output, 'evidence')}`);
      return { written };
    } catch (e) {
      if (e instanceof BundleIntegrityError) this.error(`${e.message}. Re-collect rather than editing a bundle.`, { exit: 2 });
      if (e instanceof BundleIncompleteError) this.error(e.message, { exit: 2 });
      throw e;
    }
  }
}
