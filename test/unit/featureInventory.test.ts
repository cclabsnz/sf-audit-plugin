import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { CHECKS } from '../../src/checks/registry.js';
import { NAMED_CHAINS } from '../../src/chains/namedChains.js';

/**
 * Feature-inventory guard.
 *
 * docs/FEATURES.md is the place to look before building a check, chain or command, so work is not
 * rebuilt. It only helps while it is complete: every registered check id, every named chain id and
 * every command must appear in it, wrapped in backticks so a substring of a longer id or of prose
 * cannot satisfy the match.
 */

const ROOT = process.cwd();
const FEATURES = readFileSync(join(ROOT, 'docs/FEATURES.md'), 'utf8');
const COMMANDS_DIR = join(ROOT, 'src/commands');

function commandFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return commandFiles(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts') ? [path] : [];
  });
}

/** oclif command id for a file under src/commands: audit/events/pull.ts -> "audit events pull". */
function commandId(file: string): string {
  return relative(COMMANDS_DIR, file).replace(/\.ts$/, '').split(sep).join(' ');
}

function missing(ids: readonly string[]): string[] {
  return ids.filter((id) => !FEATURES.includes(`\`${id}\``));
}

describe('docs/FEATURES.md lists everything that has been built', () => {
  it('lists every check id in CHECKS', () => {
    const ids = CHECKS.map((c) => c.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(missing(ids)).toEqual([]);
  });

  it('lists every named chain id in NAMED_CHAINS', () => {
    const ids = NAMED_CHAINS.map((c) => c.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(missing(ids)).toEqual([]);
  });

  it('lists every command under src/commands by its id', () => {
    const ids = commandFiles(COMMANDS_DIR).map(commandId);
    expect(ids).toContain('audit security'); // the walk must still find commands
    expect(missing(ids)).toEqual([]);
  });

  // Shared helpers, renderers and chain modules are what gets rewritten when nobody knows they
  // exist, so each file must be named by its repo path.
  it('names every shared helper, renderer and chain module by path', () => {
    const files = ['src/checks/support', 'src/renderers', 'src/chains']
      .flatMap((d) => commandFiles(join(ROOT, d)))
      .map((f) => relative(ROOT, f).split(sep).join('/'));
    expect(files).toContain('src/checks/support/guestShares.ts'); // the walk must still find files
    expect(files.filter((f) => !FEATURES.includes(f))).toEqual([]);
  });

  // The other direction: a row for something that no longer exists sends the next reader to
  // build on a ghost, and a row's file must be where the code is.
  const section = (heading: string): string => {
    const start = FEATURES.indexOf(`\n## ${heading}\n`);
    expect(start).toBeGreaterThan(-1);
    const end = FEATURES.indexOf('\n## ', start + 1);
    return FEATURES.slice(start, end === -1 ? undefined : end);
  };
  const rowIds = (text: string): string[] => [...text.matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1]);

  it('lists no check or chain that is not registered, and states the check count', () => {
    const checks = section('Security checks');
    const registered = new Set(CHECKS.map((c) => c.id));
    expect(rowIds(checks).filter((id) => !registered.has(id))).toEqual([]);
    expect(rowIds(checks)).toHaveLength(CHECKS.length);
    expect(checks).toContain(`All ${CHECKS.length} checks`);
    const chains = new Set(NAMED_CHAINS.map((c) => c.id));
    expect(rowIds(section('Attack chains')).filter((id) => !chains.has(id))).toEqual([]);
  });

  it('points every row at a file that exists', () => {
    const paths = [...FEATURES.matchAll(/\b((?:src|test|scripts|docs|schemas|config)\/[\w./-]+\.(?:ts|mjs|json|md|xml))\b/g)].map((m) => m[1]);
    expect(paths.length).toBeGreaterThan(100);
    expect([...new Set(paths)].filter((f) => !existsSync(join(ROOT, f)))).toEqual([]);
  });
});
