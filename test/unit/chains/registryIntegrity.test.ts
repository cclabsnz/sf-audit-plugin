import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CAPABILITY_REGISTRY } from '../../../src/chains/CapabilityRegistry.js';

/**
 * Drift guard for the attack model.
 *
 * Both halves of the chain model reference findings by *string id*, and both fail silently when a
 * string is wrong:
 *
 *   - a CAPABILITY_REGISTRY key that no check emits simply never grants anything, so the capability
 *     it was meant to contribute is missing from every chain;
 *   - a named-chain ingredient id that no check emits can never match, so that chain never fires.
 *
 * Neither shows up as a test failure anywhere else — the engine just quietly finds less. This test
 * pins both directions against the ids the checks can actually produce.
 *
 * Ids are collected from the check implementations rather than by running them, because most ids
 * are only emitted on specific org conditions that a unit test cannot reproduce in aggregate.
 */

const ROOT = process.cwd();
const IMPL_DIR = join(ROOT, 'src/checks/impl');

/** Literal finding ids, plus the static prefix of every template-literal id. */
function collectEmittableIds(): { literals: Set<string>; prefixes: Set<string> } {
  const literals = new Set<string>();
  const prefixes = new Set<string>();
  for (const file of readdirSync(IMPL_DIR).filter((f) => f.endsWith('.ts'))) {
    const src = readFileSync(join(IMPL_DIR, file), 'utf8');
    for (const m of src.matchAll(/\bid:\s*'([^']+)'/g)) literals.add(m[1]);
    // `id: `foo-${bar}`` → the emittable ids all start with "foo-"
    for (const m of src.matchAll(/\bid:\s*`([^`$]*)\$\{/g)) if (m[1]) prefixes.add(m[1]);
    // `id: `foo-bar`` with no interpolation is just a literal
    for (const m of src.matchAll(/\bid:\s*`([^`$]+)`/g)) literals.add(m[1]);
  }
  return { literals, prefixes };
}

/** Finding ids referenced as chain ingredients, i.e. inside byIds(...) / byPrefixes(...). */
function collectChainReferencedIds(): Set<string> {
  const src = readFileSync(join(ROOT, 'src/chains/namedChains.ts'), 'utf8');
  const refs = new Set<string>();
  for (const call of src.matchAll(/by(?:Ids|Prefixes)\(\s*\w+\s*,\s*\[([\s\S]*?)\]\s*\)/g)) {
    for (const q of call[1].matchAll(/'([^']+)'/g)) refs.add(q[1]);
  }
  return refs;
}

const { literals, prefixes } = collectEmittableIds();

describe('attack-model id integrity', () => {
  it('collects a plausible number of finding ids from the checks', () => {
    // Guards against the collectors silently matching nothing and the suite passing vacuously.
    expect(literals.size).toBeGreaterThan(200);
    expect(prefixes.size).toBeGreaterThan(5);
  });

  it('every CAPABILITY_REGISTRY key is a finding id some check can emit', () => {
    const emittable = (id: string): boolean =>
      literals.has(id) || [...prefixes].some((p) => id.startsWith(p));
    const orphans = Object.keys(CAPABILITY_REGISTRY).filter((id) => !emittable(id));
    expect(orphans).toEqual([]);
  });

  it('every named-chain ingredient id can be emitted by some check', () => {
    // A chain may reference either a whole id or a prefix of a family of ids, so a reference is
    // compatible if it matches a literal, extends a template prefix, or is extended by one.
    const compatible = (id: string): boolean =>
      literals.has(id) || [...prefixes].some((p) => id.startsWith(p) || p.startsWith(id));
    const unreachable = [...collectChainReferencedIds()].filter((id) => !compatible(id));
    expect(unreachable).toEqual([]);
  });

  it('finds chain ingredients at all', () => {
    expect(collectChainReferencedIds().size).toBeGreaterThan(20);
  });
});
