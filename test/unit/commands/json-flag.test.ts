import AuditAppsCommand from '../../../src/commands/audit/apps.js';
import AuditDiffCommand from '../../../src/commands/audit/diff.js';
import AuditHistoryCommand from '../../../src/commands/audit/history.js';
import AuditListCommand from '../../../src/commands/audit/list.js';
import SecurityAuditCommand from '../../../src/commands/audit/security.js';
import AuditTimelineCommand from '../../../src/commands/audit/timeline.js';
import AuditPreflightCommand from '../../../src/commands/audit/preflight.js';
import AuditEventsPullCommand from '../../../src/commands/audit/events/pull.js';

/**
 * Agent-drivability invariant.
 *
 * Every command already returns a typed, serialisable result from run(). oclif will
 * emit that result as JSON on stdout — suppressing the human progress logging — but
 * only when the command opts in via `enableJsonFlag`. Without it there is no
 * machine-readable surface at all: a caller has to scrape progress lines off stdout
 * and race the report file write.
 *
 * This is the gate that keeps `--json` working on every command, including ones
 * added later.
 */

const COMMANDS = [
  ['audit security', SecurityAuditCommand],
  ['audit list', AuditListCommand],
  ['audit history', AuditHistoryCommand],
  ['audit diff', AuditDiffCommand],
  ['audit apps', AuditAppsCommand],
  ['audit timeline', AuditTimelineCommand],
  ['audit preflight', AuditPreflightCommand],
  ['audit events pull', AuditEventsPullCommand],
] as const;

describe('--json is available on every command', () => {
  it('covers every command the plugin ships', () => {
    // Guards against the suite passing vacuously if the list above is gutted.
    expect(COMMANDS).toHaveLength(8);
  });

  it.each(COMMANDS)('%s enables the json flag', (_name, Command) => {
    expect(Command.enableJsonFlag).toBe(true);
  });
});
