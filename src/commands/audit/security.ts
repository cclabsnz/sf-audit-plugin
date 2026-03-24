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
  };

  public async run(): Promise<AuditResult> {
    const { flags } = await this.parse(SecurityAuditCommand);

    const conn = flags['target-org'].getConnection('62.0') as any;
    // Resolve plugin root from compiled file location (lib/commands/audit/security.js → 3 levels up)
    const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    const queries = QueryRegistry.load(pluginRoot);
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, queries, orgInfo);

    this.log(`Auditing org: ${orgInfo.name} (${orgInfo.id})`);

    const engine = new CheckEngine(CHECKS, ctx);
    const result = await engine.run();

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
      this.log(`Report written: ${outputPath}`);
    }

    this.log(
      `\nAudit complete — ${result.findings.length} findings | Score: ${result.healthScore}/100 | Grade: ${result.grade}`,
    );

    if (flags['fail-on']) {
      this.handleFailOn(result, flags['fail-on'] as RiskLevel);
    }

    return result;
  }

  private handleFailOn(result: AuditResult, failOn: RiskLevel): void {
    const ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const threshold = ORDER.indexOf(failOn);
    const hasViolation = result.findings.some(
      (f) => ORDER.indexOf(f.riskLevel) <= threshold,
    );
    if (hasViolation) {
      this.log(`Audit failed: one or more findings at or above ${failOn} severity.`);
      this.exit(1);
    }
  }
}
