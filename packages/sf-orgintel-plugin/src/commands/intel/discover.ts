import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { resolveOrgInfo, buildIntelContext } from '../../lib/wire.js';
import { runDiscover } from '../../discover/runDiscover.js';
import type { DiscoverResult } from '../../discover/types.js';
import { OrgIntelCache } from '../../lib/cache.js';
import { TOOL_VERSION, API_VERSION } from '../../version.js';

export default class IntelDiscoverCommand extends SfCommand<DiscoverResult> {
  public static summary = 'Discover where an org\'s business processes live (anchor ranking + domain fingerprint)';
  public static description =
    'Ranks the org\'s objects as likely business-process anchors using six deterministic, evidence-backed ' +
    'signals — automation density, a status/lifecycle-shaped field, record volume & velocity, relationship ' +
    'centrality, activity attach rate, and existing history tracking (weights live in one documented config). ' +
    'Also emits a domain-fingerprint JSON artifact (installed packages/clouds, object inventory, status ' +
    'picklists, record types, app names) — the input a future classifier will consume. Read-only and local.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --top 15 --json',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --output ./reports',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
    top: Flags.integer({
      summary: 'Number of top anchor candidates to report.',
      default: 10,
    }),
    'max-objects': Flags.integer({
      summary: 'Maximum objects to deep-analyse (key-standard + prioritised custom).',
      default: 150,
    }),
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the domain-fingerprint JSON. Defaults to current directory.',
      default: '.',
    }),
    'no-fingerprint-file': Flags.boolean({
      summary: 'Do not write the fingerprint JSON file (it is still included in --json output).',
      default: false,
    }),
  };

  public async run(): Promise<DiscoverResult> {
    const { flags } = await this.parse(IntelDiscoverCommand);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const conn = flags['target-org'].getConnection(API_VERSION) as any;
    const { orgInfo, namespace } = await resolveOrgInfo(conn);
    const ctx = buildIntelContext(conn, orgInfo, namespace, API_VERSION);

    this.log(`Discovering process anchors for org: ${orgInfo.name} (${orgInfo.id})`);
    const data = await runDiscover(ctx, { topN: flags.top, maxObjects: flags['max-objects'] });

    const result: DiscoverResult = {
      version: 1,
      provenance: {
        tool: 'orgintel',
        toolVersion: TOOL_VERSION,
        generatedAt: new Date().toISOString(),
        orgId: orgInfo.id,
      },
      ...data,
    };

    // Cache so `intel map` can show ranked anchors alongside the coupling graph.
    new OrgIntelCache(orgInfo.id).set('discover', 'latest', result);

    if (!flags['no-fingerprint-file']) {
      fs.mkdirSync(flags.output, { recursive: true });
      const file = path.join(flags.output, `orgintel-fingerprint-${orgInfo.id}-${Date.now()}.json`);
      fs.writeFileSync(file, JSON.stringify(result.fingerprint, null, 2), 'utf-8');
      this.log(`Domain fingerprint written: ${file}`);
    }

    this.printAnchors(result);
    return result;
  }

  private printAnchors(r: DiscoverResult): void {
    this.log('');
    this.log(`Analysed ${r.totalObjectsAnalyzed} object(s)${r.droppedObjects > 0 ? ` (+${r.droppedObjects} not scored)` : ''}.`);
    this.log('─────────────────────────────────────────────');
    this.log(`  Top ${r.anchors.length} process-anchor candidates`);
    this.log('─────────────────────────────────────────────');
    r.anchors.forEach((a, i) => {
      this.log(`\n  ${String(i + 1).padStart(2)}. ${a.label} (${a.object})  score ${a.score.toFixed(3)}`);
      for (const line of a.evidence) this.log(`        · ${line}`);
    });
    if (r.fingerprint.clouds.length > 0) {
      this.log(`\n  Clouds detected: ${r.fingerprint.clouds.join(', ')}`);
    }
    for (const note of r.notes) this.log(`  note: ${note}`);
  }
}
