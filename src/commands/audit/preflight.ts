import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { CHECKS } from '../../checks/registry.js';
import { buildPreflight, type PreflightResult } from '../../preflight/permissionMap.js';
import { readEffectivePermissions } from '../../preflight/readPermissions.js';
import { buildApiClients } from '../../lib/wire.js';

export default class AuditPreflightCommand extends SfCommand<PreflightResult> {
  public static summary = 'Report what this audit user will and will not be able to establish';
  public static description =
    "Reads the running user's effective permissions in a single query and reports which checks will " +
    'produce a verdict and which will return inconclusive, before an audit is run. The audit itself can ' +
    'only report a permission gap after it has already come back blind; this answers the same question ' +
    'up front, while it is still cheap to fix. Read-only, and opens no more than one query.';

  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --json',
  ];

  public static flags = {
    'target-org': Flags.requiredOrg(),
  };

  public async run(): Promise<PreflightResult> {
    const { flags } = await this.parse(AuditPreflightCommand);
    const conn = flags['target-org'].getConnection();
    const { soql } = buildApiClients(conn);

    const granted = await readEffectivePermissions(soql);
    const preflight = buildPreflight(granted, CHECKS);

    this.printPreflight(preflight);
    return preflight;
  }

  private printPreflight(p: PreflightResult): void {
    this.log('');
    if (p.missing.length === 0) {
      this.log(`  All ${CHECKS.length} checks can gather evidence. Nothing to grant.`);
      this.log('');
      return;
    }

    this.log(`  ${p.willRun} of ${CHECKS.length} checks can gather evidence.`);
    if (p.willBeInconclusive.length > 0) {
      this.log(`  ${p.willBeInconclusive.length} will return inconclusive as things stand.`);
    }
    this.log('');
    this.log('  Missing permissions');
    this.log('  ───────────────────');
    for (const m of p.missing) {
      this.log(`  ${m.blocking ? '[blocking] ' : ''}${m.label} (${m.permission})`);
      this.log(`    ${m.impact}`);
      if (m.affectedChecks.length > 0) {
        this.log(`    Affects ${m.affectedChecks.length} check${m.affectedChecks.length !== 1 ? 's' : ''}: ${m.affectedChecks.join(', ')}`);
      }
      this.log('');
    }

    if (!p.canRun) {
      this.log('  The audit cannot run at all until the blocking permission is granted.');
      this.log('');
    }
  }
}
