import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Documentation-drift guard.
 *
 * The full check inventory lives in docs/CHECKS.md; the README carries a per-domain summary. Both
 * are advertised to clients, so both must stay pinned to `src/checks/registry.ts` — a count that
 * silently falls behind describes an audit the tool no longer performs.
 *
 * The summary is the newer risk: it restates the numbers in a second place, which is exactly how a
 * stale "82 checks" survived in project docs before. So it is checked against the inventory
 * per domain, not just in total.
 */

const ROOT = process.cwd();
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
const CHECKS_DOC = readFileSync(join(ROOT, 'docs/CHECKS.md'), 'utf8');

/** Count `new XxxCheck()` entries inside the exported CHECKS array. */
function registeredCheckCount(): number {
  const src = readFileSync(join(ROOT, 'src/checks/registry.ts'), 'utf8');
  const start = src.indexOf('export const CHECKS');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf('];', start);
  expect(end).toBeGreaterThan(start);
  return (src.slice(start, end).match(/new\s+[A-Za-z0-9_]+Check\s*\(/g) ?? []).length;
}

const isCheckRow = (l: string): boolean =>
  l.startsWith('| ') && !/^\|\s*(Check\b|Domain\b|:?-{2,})/.test(l);

/** docs/CHECKS.md, grouped by its `## <domain>` headings. */
function inventoryByDomain(): Map<string, number> {
  const out = new Map<string, number>();
  let domain = '';
  for (const line of CHECKS_DOC.split('\n')) {
    const h = /^## (.+)$/.exec(line);
    if (h) { domain = h[1].trim(); continue; }
    if (domain && isCheckRow(line)) out.set(domain, (out.get(domain) ?? 0) + 1);
  }
  return out;
}

/** The README's "Domain | Checks" summary table. */
function readmeSummary(): Map<string, number> {
  const from = README.indexOf('## What It Checks');
  const to = README.indexOf('## Compliance frameworks');
  expect(from).toBeGreaterThanOrEqual(0);
  expect(to).toBeGreaterThan(from);
  const out = new Map<string, number>();
  for (const line of README.slice(from, to).split('\n')) {
    const m = /^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|/.exec(line);
    if (m) out.set(m[1].trim(), Number(m[2]));
  }
  return out;
}

const N = registeredCheckCount();

describe('check counts stay in sync with the registry', () => {
  it('registers a plausible number of checks', () => {
    expect(N).toBeGreaterThan(50);
  });

  it('docs/CHECKS.md lists exactly N checks', () => {
    const total = [...inventoryByDomain().values()].reduce((a, b) => a + b, 0);
    expect(total).toBe(N);
  });

  // The inventory's own headline sentence is a third place the number is written down, and it is
  // how docs/CHECKS.md drifted to a stale "88" while its table was correct.
  it('the docs/CHECKS.md headline matches the registry', () => {
    const nums = [...CHECKS_DOC.matchAll(/\*\*(\d+) read-only checks\*\*/g)].map((m) => Number(m[1]));
    expect(nums.length).toBeGreaterThan(0);
    for (const n of nums) expect(n).toBe(N);
  });

  it('the README headline matches the registry', () => {
    const nums = [...README.matchAll(/\*\*(\d+) read-only checks\*\*/g)].map((m) => Number(m[1]));
    expect(nums.length).toBeGreaterThan(0);
    for (const n of nums) expect(n).toBe(N);
  });

  it('"all N checks" in usage matches the registry', () => {
    const nums = [...README.matchAll(/all (\d+) checks/g)].map((m) => Number(m[1]));
    expect(nums.length).toBeGreaterThan(0);
    for (const n of nums) expect(n).toBe(N);
  });

  it('the README domain summary sums to N', () => {
    const total = [...readmeSummary().values()].reduce((a, b) => a + b, 0);
    expect(total).toBe(N);
  });

  it('every README domain count matches docs/CHECKS.md for that domain', () => {
    const inventory = inventoryByDomain();
    const summary = readmeSummary();
    expect(summary.size).toBeGreaterThan(5);
    const mismatches: string[] = [];
    for (const [domain, count] of summary) {
      const actual = inventory.get(domain);
      if (actual !== count) mismatches.push(`${domain}: README ${count}, docs/CHECKS.md ${actual ?? 'absent'}`);
    }
    expect(mismatches).toEqual([]);
  });
});
