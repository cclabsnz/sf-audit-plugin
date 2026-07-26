import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import type { AuditResult } from '../../findings/AuditResult.js';
import type { RiskLevel } from '@cclabsnz/sf-core';
import { CheckEngine } from '../../checks/CheckEngine.js';
import { CHECKS } from '../../checks/registry.js';
import { JsonRenderer } from '../../renderers/JsonRenderer.js';
import { HtmlRenderer } from '../../renderers/HtmlRenderer.js';
import { MarkdownRenderer } from '../../renderers/MarkdownRenderer.js';
import type { AuditRenderer } from '../../renderers/AuditRenderer.js';
import { ClientReportRenderer } from '../../renderers/ClientReportRenderer.js';
import { resolveBranding, type BrandingOverrides } from '@cclabsnz/sf-core';
import { resolveFrameworks } from '../../compliance/resolve.js';
import { buildAuditContext, resolveOrgInfo } from '../../lib/wire.js';
import { loadScoringConfig } from '../../findings/loadScoringConfig.js';
import { HistoryStore } from '../../history/HistoryStore.js';

const RENDERERS: Record<string, AuditRenderer> = {
  html: new HtmlRenderer(),
  md: new MarkdownRenderer(),
  json: new JsonRenderer(),
};

export default class SecurityAuditCommand extends SfCommand<AuditResult> {
  public static summary = 'Run a comprehensive security audit against a Salesforce org';
  public static description =
    'Runs all security checks against the target org and writes a report file.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --format json --output ./reports',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --fail-on HIGH',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    format: Flags.string({
      char: 'f',
      summary: 'Output format(s), comma-separated: html, md, json, executive',
      default: 'html',
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the report. Defaults to current directory.',
      default: '.',
    }),
    'fail-on': Flags.string({
      summary: 'Exit with code 1 if any finding is at or above this severity.',
      options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    }),
    checks: Flags.string({
      summary: 'Comma-separated check IDs to run. Omit to run all checks.',
      helpValue: 'hardcoded-credentials,apex-sharing',
    }),
    'scoring-config': Flags.string({
      summary: 'Path to a custom scoring config JSON file. Merges with defaults.',
      helpValue: './hnz-scoring.json',
    }),
    'prepared-for': Flags.string({
      summary: 'Client name for the executive report cover line.',
    }),
    branding: Flags.string({
      summary: 'Path to a report-branding.json to override CloudCounsel defaults (executive format).',
      helpValue: './report-branding.json',
    }),
    top: Flags.integer({
      summary: 'Number of executive priorities to highlight (executive format).',
      default: 5,
    }),
    frameworks: Flags.string({
      summary: 'Compliance frameworks for the executive matrix: universal | nz | all | a comma list (executive format).',
      default: 'universal',
    }),
    'resolve-domains': Flags.boolean({
      summary:
        'Make outbound DNS queries from this machine to verify CSP trusted domains resolve. Off by default; default runs contact only the target org.',
      default: false,
    }),
  };

  public async run(): Promise<AuditResult> {
    const { flags } = await this.parse(SecurityAuditCommand);

    // Validate the selection and output formats up front, so a typo fails fast with
    // a clear message instead of silently running a partial/empty audit or writing
    // no report after the (potentially long) run completes.
    const checksToRun = this.resolveChecks(flags.checks);
    const formats = this.resolveFormats(flags.format);

    const conn = flags['target-org'].getConnection('62.0') as any;
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, orgInfo, {
      resolveDomains: flags['resolve-domains'],
    });

    const knownCheckIds = new Set(CHECKS.map((c) => c.id));
    const scoringConfig = loadScoringConfig(
      flags['scoring-config'],
      knownCheckIds,
      (msg) => this.warn(msg),
    );

    this.log(`Auditing org: ${orgInfo.name} (${orgInfo.id})`);
    if (flags.checks) this.log(`Running ${checksToRun.length} of ${CHECKS.length} checks`);

    const engine = new CheckEngine(checksToRun, ctx, scoringConfig);
    const result = await engine.run((current, total, checkName) => {
      this.log(`[${String(current).padStart(2)}/${total}] ${checkName}`);
    });

    fs.mkdirSync(flags.output, { recursive: true });
    for (const format of formats) {
      const renderer = this.rendererFor(format, flags);
      if (!renderer) continue; // unreachable: formats validated up front
      const output = renderer.render(result);
      const prefix = renderer.filenamePrefix ?? 'sf-audit';
      const filename = `${prefix}-${orgInfo.id}-${Date.now()}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, output, 'utf-8');
      this.log(`\nReport written: ${outputPath}`);
    }

    // Auto-archive: silently save a copy for history tracking
    const store = new HistoryStore();
    store.archive(result);

    this.log('');
    this.printSummary(result);

    if (flags['fail-on']) {
      this.handleFailOn(result, flags['fail-on'] as RiskLevel);
    }

    return result;
  }

  /** Resolve --checks to the checks to run, erroring on any unknown ID. */
  private resolveChecks(raw?: string): typeof CHECKS {
    if (!raw) return CHECKS;
    const ids = raw.split(',').map((s) => s.trim()).filter(Boolean);
    const unknown = ids.filter((id) => !CHECKS.some((c) => c.id === id));
    if (unknown.length > 0) {
      this.error(`Unknown check ID(s): ${unknown.join(', ')}`, {
        suggestions: ["Run 'sf audit list' to see all valid check IDs."],
      });
    }
    const set = new Set(ids);
    const selected = CHECKS.filter((c) => set.has(c.id));
    if (selected.length === 0) {
      this.error('No checks were selected by --checks.', {
        suggestions: ["Run 'sf audit list' to see valid check IDs, or omit --checks to run all."],
      });
    }
    return selected;
  }

  /** Resolve --format to a validated list, erroring on any unknown format. */
  private resolveFormats(raw: string): string[] {
    const valid = ['html', 'md', 'json', 'executive'];
    const formats = raw.split(',').map((f) => f.trim()).filter(Boolean);
    const bad = formats.filter((f) => !valid.includes(f));
    if (bad.length > 0 || formats.length === 0) {
      this.error(bad.length > 0 ? `Unknown output format(s): ${bad.join(', ')}` : 'No output format specified.', {
        suggestions: [`Valid formats: ${valid.join(', ')}`],
      });
    }
    return formats;
  }

  private rendererFor(
    format: string,
    flags: { 'prepared-for'?: string; branding?: string; top: number; frameworks: string },
  ): AuditRenderer | undefined {
    if (format === 'executive') {
      let overrides: BrandingOverrides | undefined;
      if (flags.branding) overrides = JSON.parse(fs.readFileSync(flags.branding, 'utf-8')) as BrandingOverrides;
      const branding = resolveBranding(overrides, flags['prepared-for']);
      return new ClientReportRenderer({ branding, topN: flags.top, frameworks: resolveFrameworks(flags.frameworks) });
    }
    return RENDERERS[format];
  }

  private printSummary(result: AuditResult): void {
    const levels: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const counts = Object.fromEntries(
      levels.map((l) => [l, result.findings.filter((f) => f.riskLevel === l).length]),
    ) as Record<RiskLevel, number>;

    this.log('─────────────────────────────');
    this.log('  Audit Summary');
    this.log('─────────────────────────────');
    for (const level of levels) {
      this.log(`  ${level.padEnd(10)}  ${String(counts[level]).padStart(3)} finding${counts[level] !== 1 ? 's' : ''}`);
    }
    this.log('─────────────────────────────');
    this.log(`  Score: ${result.healthScore}/100   Grade: ${result.grade}`);
    this.log('─────────────────────────────');
  }

  private handleFailOn(result: AuditResult, failOn: RiskLevel): void {
    const ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const threshold = ORDER.indexOf(failOn);
    const violations = result.findings.filter((f) => ORDER.indexOf(f.riskLevel) <= threshold);
    if (violations.length > 0) {
      this.log(`\nFail-on threshold: ${failOn}, ${violations.length} finding${violations.length !== 1 ? 's' : ''} at or above threshold:`);
      for (const f of violations) {
        this.log(`  [${f.riskLevel}] ${f.title}`);
      }
      this.exit(1);
    }
  }
}
