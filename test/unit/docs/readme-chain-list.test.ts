import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';

/**
 * Documentation-drift guard for the attack-chain list.
 *
 * The table lives in docs/ATTACK-CHAINS.md and the README carries the narrative plus a count. Both
 * are client-facing, and a list that silently falls behind namedChains.ts describes an audit the
 * tool no longer performs.
 *
 * Pins: one table row per named chain, each chain's title and severity on the same row, the count
 * spelled correctly in the README prose, and that the table never drifts back into the range the
 * check-count guard scans.
 */

const ROOT = process.cwd();
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
const CHAINS_DOC = readFileSync(join(ROOT, 'docs/ATTACK-CHAINS.md'), 'utf8');

function chainTableRows(): string[] {
  return CHAINS_DOC
    .split('\n')
    .filter((l) => l.startsWith('| '))
    .filter((l) => !/^\|\s*(Chain\b|:?-{2,})/.test(l));
}

const NUMBER_WORDS: Record<number, string> = {
  8: 'eight', 9: 'nine', 10: 'ten', 11: 'eleven', 12: 'twelve', 13: 'thirteen', 14: 'fourteen',
};

describe('attack-chain docs stay in sync with namedChains.ts', () => {
  it('lists exactly one table row per named chain', () => {
    expect(chainTableRows()).toHaveLength(NAMED_CHAINS.length);
  });

  it('documents every chain title with its severity on the same row', () => {
    const rows = chainTableRows();
    for (const chain of NAMED_CHAINS) {
      const row = rows.find((l) => l.includes(chain.title));
      expect(row).toBeDefined();
      expect(row).toContain(chain.severity);
    }
  });

  it('states the chain count correctly in the README prose', () => {
    const word = NUMBER_WORDS[NAMED_CHAINS.length];
    expect(word).toBeDefined(); // extend NUMBER_WORDS if this fires
    expect(README.toLowerCase()).toContain(`${word} named chains`);
  });

  it('keeps the chain table out of the check-count guard\'s range', () => {
    // readme-check-count counts every "| " row between "What It Checks" and "Compliance
    // frameworks". A chain table there would be miscounted as checks.
    const range = README.slice(
      README.indexOf('## What It Checks'),
      README.indexOf('## Compliance frameworks'),
    );
    for (const chain of NAMED_CHAINS) expect(range).not.toContain(chain.title);
  });
});
