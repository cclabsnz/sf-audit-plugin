import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { buildAuditContext, resolveOrgInfo } from '../../../lib/wire.js';
import { collectBundle, defaultIncidentRoot } from '../../../incident/collect/collectBundle.js';

export interface IncidentCollectResult { dir: string; waves: number; logsCollected: number; logsMissing: number }

export default class AuditIncidentCollectCommand extends SfCommand<IncidentCollectResult> {
  public static summary = 'Collect a guest-filtered evidence bundle for a Guest User Anomaly investigation';
  public static description =
    'Read-only. Finds Guest User Anomaly waves, downloads the event logs for each wave day plus one baseline day either side, ' +
    'keeps only guest-user rows, and snapshots the audit trail, logins and guest configuration into a hashed bundle. ' +
    'Each raw log is staged on disk while it is filtered: allow ~600 MB free on a heavy day. ' +
    'Hosting classification uses only the --ip-ranges files you supply; nothing is downloaded from anywhere but the org.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --since 120 --ip-ranges ./ip-ranges.json',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --window 2026-09-14/2026-09-16',
  ];
  public static flags = {
    'target-org': Flags.requiredOrg(),
    since: Flags.integer({ summary: 'Days of Guest User Anomaly events to read (max 365).', default: 30, min: 1, max: 365 }),
    window: Flags.string({ summary: 'Explicit day window instead of discovery: YYYY-MM-DD/YYYY-MM-DD or YYYY-MM-DD/PnD (max 31 days).', helpValue: '2026-09-14/2026-09-16' }),
    event: Flags.string({ summary: 'Keep only the wave containing this EventIdentifier.' }),
    'ip-ranges': Flags.string({ summary: 'Local provider range file (AWS ip-ranges.json, GCP cloud.json, Azure service tags, or CIDR list). Repeatable.', multiple: true }),
    output: Flags.string({ summary: 'Bundle directory. Defaults to ~/.sf/incidents/{orgId}/{timestamp}.' }),
  };

  public async run(): Promise<IncidentCollectResult> {
    const { flags } = await this.parse(AuditIncidentCollectCommand);
    const conn = flags['target-org'].getConnection('62.0') as any;
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, orgInfo);
    const dir = flags.output ?? path.join(defaultIncidentRoot(), orgInfo.id, new Date().toISOString().replace(/[:.]/g, '-'));
    this.log(`Collecting incident bundle for ${orgInfo.name} (${orgInfo.id}) into ${dir}`);
    let manifest: Awaited<ReturnType<typeof collectBundle>>['manifest'];
    try {
      ({ manifest } = await collectBundle(
        { soql: ctx.soql, rest: ctx.rest, orgId: orgInfo.id, orgName: orgInfo.name },
        { sinceDays: flags.since, window: flags.window, event: flags.event, ipRangeFiles: flags['ip-ranges'] ?? [], outputDir: dir, warn: (m) => this.warn(m) },
      ));
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      this.error(`${message} (partial bundle kept at ${dir}; re-run with --output "${dir}" to resume)`, { exit: 1 });
    }
    const collected = manifest.logs.filter((l) => l.status === 'collected').length;
    const missing = manifest.logs.length - collected;
    this.log(`${manifest.waves.length} wave(s); ${collected} log file(s) collected, ${missing} not available.`);
    this.log(`Next: sf audit incident report --bundle "${dir}"`);
    return { dir, waves: manifest.waves.length, logsCollected: collected, logsMissing: missing };
  }
}
