import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * A non-zero exit must not destroy the JSON result.
 *
 * `this.exit(n)` throws an ExitError. SfCommand.catch() turns any thrown error into
 * the JSON *error* envelope, so a command that exits this way under `--json` returns
 * an error instead of its result — the caller loses the audit report precisely when
 * findings exist and it matters most.
 *
 * Setting `process.exitCode` instead lets run() return normally: oclif prints the
 * result, and the process still exits non-zero.
 */

const SECURITY_CMD = join(process.cwd(), 'src/commands/audit/security.ts');

/** Strip block and line comments so the scan reads code, not prose about code. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

describe('non-zero exit preserves the JSON result', () => {
  const source = stripComments(readFileSync(SECURITY_CMD, 'utf-8'));

  it('reads the command source', () => {
    // Vacuity guard: a moved or renamed file must fail loudly, not pass silently.
    expect(source.length).toBeGreaterThan(1000);
    expect(source).toContain('resolveExitCode');
  });

  it('does not call this.exit() to signal audit outcome', () => {
    expect(source).not.toMatch(/this\.exit\(/);
  });

  it('sets process.exitCode instead', () => {
    expect(source).toMatch(/process\.exitCode\s*=/);
  });
});
