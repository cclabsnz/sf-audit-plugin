import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';

/**
 * Documentation-drift guard for the README's "Attack chains" section.
 *
 * The same guard the check count gets (`readme-check-count.test.ts`), for the same reason: the
 * README advertises the named chains to clients, and a list that silently falls behind
 * `namedChains.ts` is worse than no list — it describes an audit the tool no longer performs.
 *
 * Pins three things against NAMED_CHAINS:
 *   1. the table lists exactly one row per named chain,
 *   2. every chain's title and severity appear, spelled the same way as in code,
 *   3. the prose count ("The eleven named chains") matches too.
 */

const ROOT = process.cwd();
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');

/** The "## Attack chains" section, which must sit outside the check-count guard's range. */
function chainSection(): string {
  const from = README.indexOf('## Attack chains');
  const to = README.indexOf('## Scope & Liability');
  expect(from).toBeGreaterThanOrEqual(0);
  expect(to).toBeGreaterThan(from);
  return README.slice(from, to);
}

function chainTableRows(): string[] {
  return chainSection()
    .split('\n')
    .filter((l) => l.startsWith('| '))
    .filter((l) => !/^\|\s*(Chain\b|:?-{2,})/.test(l));
}

const NUMBER_WORDS: Record<number, string> = {
  8: 'eight', 9: 'nine', 10: 'ten', 11: 'eleven', 12: 'twelve', 13: 'thirteen', 14: 'fourteen',
};

describe('README attack-chain list stays in sync with namedChains.ts', () => {
  it('lists exactly one table row per named chain', () => {
    expect(chainTableRows()).toHaveLength(NAMED_CHAINS.length);
  });

  it('documents every chain title and its severity', () => {
    const section = chainSection();
    for (const chain of NAMED_CHAINS) {
      expect(section).toContain(chain.title);
      // The title and severity must be on the same row, not merely both present somewhere.
      const row = chainTableRows().find((l) => l.includes(chain.title));
      expect(row).toBeDefined();
      expect(row).toContain(chain.severity);
    }
  });

  it('states the chain count correctly in prose', () => {
    const word = NUMBER_WORDS[NAMED_CHAINS.length];
    expect(word).toBeDefined(); // extend NUMBER_WORDS if this fires
    expect(README).toContain(`The ${word} named chains`);
    expect(README).toContain(`${word} modelled chains`);
  });

  it('keeps the chain table out of the check-count guard\'s range', () => {
    // readme-check-count counts every "| " row between these two headings, so an attack-chain
    // table placed there would be counted as checks and break that test instead of this one.
    const checksFrom = README.indexOf('## What It Checks');
    const complianceFrom = README.indexOf('## Compliance frameworks');
    const chainsFrom = README.indexOf('## Attack chains');
    expect(chainsFrom).toBeGreaterThan(checksFrom);
    expect(chainsFrom).toBeGreaterThan(complianceFrom);
  });
});
