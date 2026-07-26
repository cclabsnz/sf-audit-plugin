import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import type { CouplingGraph, LandscapeManifest, EvidenceTier } from '@cclabsnz/sf-core';
import { resolveBranding, type BrandingOverrides } from '@cclabsnz/sf-core';
import { resolveOrgInfo, buildIntelContext } from '../../lib/wire.js';
import { runMap } from '../../map/runMap.js';
import { renderMapHtml, type MapAnchorRow } from '../../report/mapReport.js';
import { OrgIntelCache } from '../../lib/cache.js';
import { TOOL_VERSION, API_VERSION } from '../../version.js';

interface MapCommandResult {
  couplingGraph: CouplingGraph;
  manifest: LandscapeManifest;
  flowsAnalyzed: number;
  apexClassesAnalyzed: number;
  apexTriggersAnalyzed: number;
}

export default class IntelMapCommand extends SfCommand<MapCommandResult> {
  public static summary = 'Map which objects are coupled into cross-cutting processes, and by what automation';
  public static description =
    'Parses Active flows (Flow XML) and Apex (SymbolTable, with a body-regex fallback) to build a cross-object ' +
    'coupling graph: object-pair couplings aggregated across flows, triggers, and classes with weights, ' +
    'operations, contributing components, and confidence. Emits coupling-graph.json and landscape-manifest.json ' +
    '(versioned IR contracts) and, with --html, a branded report with a static coupling graph. Read-only and ' +
    'deterministic — same org in, same graph out.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --html --output ./reports',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --include-inactive --json',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    'include-inactive': Flags.boolean({
      summary: 'Analyse inactive flows too (default: Active flows only).',
      default: false,
    }),
    html: Flags.boolean({ summary: 'Also write a branded HTML coupling report.', default: false }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write coupling-graph.json, landscape-manifest.json, and the --html report.',
      default: '.',
    }),
    branding: Flags.string({
      summary: 'Path to a report-branding.json to override CloudCounsel defaults (HTML report).',
      helpValue: './report-branding.json',
    }),
    'prepared-for': Flags.string({ summary: 'Client name for the HTML report cover line.' }),
  };

  public async run(): Promise<MapCommandResult> {
    const { flags } = await this.parse(IntelMapCommand);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const conn = flags['target-org'].getConnection(API_VERSION) as any;
    const { orgInfo, namespace } = await resolveOrgInfo(conn);
    const ctx = buildIntelContext(conn, orgInfo, namespace, API_VERSION);
    const cache = new OrgIntelCache(orgInfo.id);

    const { evidenceTier, anchors } = this.readCached(cache);

    this.log(`Mapping cross-object couplings for org: ${orgInfo.name} (${orgInfo.id})`);
    const result = await runMap(
      ctx,
      { generatedAt: new Date().toISOString(), toolVersion: TOOL_VERSION, orgId: orgInfo.id, evidenceTier },
      { includeInactive: flags['include-inactive'], cache },
    );

    fs.mkdirSync(flags.output, { recursive: true });
    const graphPath = path.join(flags.output, 'coupling-graph.json');
    const manifestPath = path.join(flags.output, 'landscape-manifest.json');
    fs.writeFileSync(graphPath, JSON.stringify(result.couplingGraph, null, 2), 'utf-8');
    fs.writeFileSync(manifestPath, JSON.stringify(result.manifest, null, 2), 'utf-8');
    this.log(`IR written: ${graphPath}`);
    this.log(`IR written: ${manifestPath}`);

    if (flags.html) {
      const overrides = flags.branding
        ? (JSON.parse(fs.readFileSync(flags.branding, 'utf-8')) as BrandingOverrides)
        : undefined;
      const branding = resolveBranding(overrides, flags['prepared-for']);
      const html = renderMapHtml({
        orgName: orgInfo.name,
        couplingGraph: result.couplingGraph,
        clusters: result.clusters,
        layout: result.layout,
        anchors,
        evidenceTier,
        flowsAnalyzed: result.flowsAnalyzed,
        apexClassesAnalyzed: result.apexClassesAnalyzed,
        apexTriggersAnalyzed: result.apexTriggersAnalyzed,
        generatedAt: result.couplingGraph.provenance.generatedAt,
        branding,
      });
      const htmlPath = path.join(flags.output, `orgintel-map-${orgInfo.id}-${Date.now()}.html`);
      fs.writeFileSync(htmlPath, html, 'utf-8');
      this.log(`Report written: ${htmlPath}`);
    }

    this.printSummary(result, evidenceTier);
    for (const note of result.notes) this.log(`  note: ${note}`);

    return {
      couplingGraph: result.couplingGraph,
      manifest: result.manifest,
      flowsAnalyzed: result.flowsAnalyzed,
      apexClassesAnalyzed: result.apexClassesAnalyzed,
      apexTriggersAnalyzed: result.apexTriggersAnalyzed,
    };
  }

  /** Read the evidence tier from a cached probe and anchors from a cached discover, if present. */
  private readCached(cache: OrgIntelCache): { evidenceTier: EvidenceTier; anchors?: MapAnchorRow[] } {
    const probe = cache.get<{ evidenceTier: EvidenceTier }>('probe', 'latest');
    const discover = cache.get<{ anchors: Array<{ object: string; label: string; score: number }> }>('discover', 'latest');
    return {
      evidenceTier: probe?.evidenceTier ?? 'C',
      anchors: discover?.anchors?.map((a) => ({ object: a.object, label: a.label, score: a.score })),
    };
  }

  private printSummary(result: { couplingGraph: CouplingGraph; clusters: unknown[] }, tier: EvidenceTier): void {
    const g = result.couplingGraph;
    this.log('');
    this.log('─────────────────────────────────────────');
    this.log(`  Evidence tier: ${tier}`);
    this.log(`  Objects: ${g.nodes.length}   Coupled pairs: ${g.edges.length}   Domains: ${result.clusters.length}`);
    this.log('─────────────────────────────────────────');
    this.log('  Top process backbones:');
    for (const e of g.edges.slice(0, 8)) {
      this.log(`   ${e.from} ↔ ${e.to}  (weight ${e.weight}, ${e.operations.join('/')})`);
    }
    this.log('─────────────────────────────────────────');
  }
}
