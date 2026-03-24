import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import type { AuditResult } from '../../findings/AuditResult.js';
import type { RiskLevel } from '../../findings/RiskLevel.js';
import { QueryRegistry } from '../../queries/QueryRegistry.js';
import { CheckEngine } from '../../checks/CheckEngine.js';
import { CHECKS } from '../../checks/registry.js';
import { JsonRenderer } from '../../renderers/JsonRenderer.js';
import { HtmlRenderer } from '../../renderers/HtmlRenderer.js';
import { MarkdownRenderer } from '../../renderers/MarkdownRenderer.js';
import type { AuditRenderer } from '../../renderers/AuditRenderer.js';
import { buildAuditContext, resolveOrgInfo } from '../../lib/wire.js';

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
      summary: 'Output format(s), comma-separated: html, md, json',
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
  };

  public async run(): Promise<AuditResult> {
    const { flags } = await this.parse(SecurityAuditCommand);

    const conn = flags['target-org'].getConnection('62.0') as any;
    // Resolve plugin root from compiled file location (lib/commands/audit/security.js → 3 levels up)
    const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    const queries = QueryRegistry.load(pluginRoot);
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, queries, orgInfo);

    const checksToRun = flags.checks
      ? (() => {
          const ids = new Set(flags.checks.split(',').map((s) => s.trim()));
          const unknown = [...ids].filter((id) => !CHECKS.some((c) => c.id === id));
          if (unknown.length > 0) {
            this.warn(`Unknown check ID(s): ${unknown.join(', ')}. Run 'sf audit list' to see available checks.`);
          }
          return CHECKS.filter((c) => ids.has(c.id));
        })()
      : CHECKS;

    this.log(`Auditing org: ${orgInfo.name} (${orgInfo.id})`);
    if (flags.checks) this.log(`Running ${checksToRun.length} of ${CHECKS.length} checks`);

    const engine = new CheckEngine(checksToRun, ctx);
    const result = await engine.run((current, total, checkName) => {
      this.log(`[${String(current).padStart(2)}/${total}] ${checkName}`);
    });

    const formats = flags.format.split(',').map((f) => f.trim());
    for (const format of formats) {
      const renderer = RENDERERS[format];
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, md, json`);
        continue;
      }
      const output = renderer.render(result);
      const filename = `sf-audit-${orgInfo.id}-${Date.now()}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, output, 'utf-8');
      this.log(`\nReport written: ${outputPath}`);
    }

    this.log('');
    this.printSummary(result);

    if (flags['fail-on']) {
      this.handleFailOn(result, flags['fail-on'] as RiskLevel);
    }

    return result;
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
      this.log(`\nFail-on threshold: ${failOn} — ${violations.length} finding${violations.length !== 1 ? 's' : ''} at or above threshold:`);
      for (const f of violations) {
        this.log(`  [${f.riskLevel}] ${f.title}`);
      }
      this.exit(1);
    }
  }
}
