import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { resolveBranding, type BrandingOverrides } from '@cclabsnz/sf-core';
import { resolveOrgInfo, buildIntelContext } from '../../lib/wire.js';
import { runProbe } from '../../probe/runProbe.js';
import type { ProbeResult } from '../../probe/types.js';
import { renderProbeHtml } from '../../report/probeReport.js';
import { OrgIntelCache } from '../../lib/cache.js';
import { TOOL_VERSION, API_VERSION } from '../../version.js';

export default class IntelProbeCommand extends SfCommand<ProbeResult> {
  public static summary = 'Probe what an org can tell you about itself (capability & evidence coverage)';
  public static description =
    'Runs a read-only capability probe against the target org and prints an evidence-coverage report: ' +
    'org basics, Event Monitoring level, field-history coverage, and the behavioural tables (with 12-month ' +
    'row counts) that reveal how the org is used. Produces an evidence-tier grade (A-D) and concrete ' +
    '"flip these switches to see more" recommendations. Entirely local and deterministic — the only network ' +
    'calls are read-only queries to the authenticated org.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --json',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --html --output ./reports',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    html: Flags.boolean({
      summary: 'Also write a branded HTML evidence-coverage report.',
      default: false,
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the --html report. Defaults to current directory.',
      default: '.',
    }),
    branding: Flags.string({
      summary: 'Path to a report-branding.json to override CloudCounsel defaults (HTML report).',
      helpValue: './report-branding.json',
    }),
    'prepared-for': Flags.string({
      summary: 'Client name for the HTML report cover line.',
    }),
  };

  public async run(): Promise<ProbeResult> {
    const { flags } = await this.parse(IntelProbeCommand);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const conn = flags['target-org'].getConnection(API_VERSION) as any;
    const { orgInfo, namespace } = await resolveOrgInfo(conn);
    const ctx = buildIntelContext(conn, orgInfo, namespace, API_VERSION);

    this.log(`Probing org: ${orgInfo.name} (${orgInfo.id})`);
    const data = await runProbe(ctx);

    const result: ProbeResult = {
      version: 1,
      provenance: {
        tool: 'orgintel',
        toolVersion: TOOL_VERSION,
        generatedAt: new Date().toISOString(),
        orgId: orgInfo.id,
      },
      ...data,
    };

    // Cache the result so `intel map`/`discover` can reuse the evidence tier.
    new OrgIntelCache(orgInfo.id).set('probe', 'latest', result);

    if (flags.html) {
      const overrides = flags.branding
        ? (JSON.parse(fs.readFileSync(flags.branding, 'utf-8')) as BrandingOverrides)
        : undefined;
      const branding = resolveBranding(overrides, flags['prepared-for']);
      fs.mkdirSync(flags.output, { recursive: true });
      const file = path.join(flags.output, `orgintel-probe-${orgInfo.id}-${Date.now()}.html`);
      fs.writeFileSync(file, renderProbeHtml(result, branding), 'utf-8');
      this.log(`\nReport written: ${file}`);
    }

    this.printSummary(result);
    return result;
  }

  private printSummary(r: ProbeResult): void {
    this.log('');
    this.log('─────────────────────────────────────────');
    this.log(`  Evidence tier: ${r.evidenceTier}`);
    this.log('─────────────────────────────────────────');
    for (const row of r.coverage) {
      this.log(`  ${row.source.padEnd(20)} ${row.status.padEnd(8)} ${row.detail}`);
    }
    this.log('─────────────────────────────────────────');
    this.log(`  Event Monitoring : ${r.eventMonitoring.level} (${r.eventMonitoring.access})`);
    this.log(`  Field history    : ${r.fieldHistory.trackedObjectCount} object(s) tracked` +
      `${r.fieldHistory.fieldAuditTrail ? ', Field Audit Trail on' : ''}`);
    const readable = r.behavioralTables.tables.filter((t) => t.access === 'ok').length;
    this.log(`  Behavioral tables: ${readable}/${r.behavioralTables.tables.length} readable`);
    this.log('─────────────────────────────────────────');
    if (r.recommendations.length > 0) {
      this.log('  Recommendations:');
      for (const rec of r.recommendations) {
        this.log(`   • [${rec.priority}] ${rec.title}`);
      }
    }
  }
}
