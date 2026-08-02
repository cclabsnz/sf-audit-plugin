import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Documentation-drift guard.
 *
 * The public README advertises an exact number of security checks (headline + the
 * "What It Checks" tables). That count is only trustworthy if it can never silently
 * fall out of sync with the actual registry. This test makes the README the enforced
 * mirror of `src/checks/registry.ts`: add or remove a check without updating the README
 * and CI (the `build-test` job, a required check on `main`) fails.
 *
 * It checks three things against the registry count N:
 *   1. the headline "**N read-only checks**" (every occurrence),
 *   2. "all N security checks" in the usage section,
 *   3. the number of check rows in the "## What It Checks" tables.
 */

const ROOT = process.cwd();

/** Count `new XxxCheck()` entries inside the exported CHECKS array. */
function registeredCheckCount(): number {
  const src = readFileSync(join(ROOT, 'src/checks/registry.ts'), 'utf8');
  const start = src.indexOf('export const CHECKS');
  expect(start).toBeGreaterThanOrEqual(0); // CHECKS array must exist
  const end = src.indexOf('];', start);
  expect(end).toBeGreaterThan(start);
  const body = src.slice(start, end);
  return (body.match(/new\s+[A-Za-z0-9_]+Check\s*\(/g) ?? []).length;
}

/** Count the check rows in the "## What It Checks" section of the README. */
function readmeTableRowCount(readme: string): number {
  const from = readme.indexOf('## What It Checks');
  const to = readme.indexOf('## Compliance frameworks');
  expect(from).toBeGreaterThanOrEqual(0);
  expect(to).toBeGreaterThan(from);
  return readme
    .slice(from, to)
    .split('\n')
    .filter((l) => l.startsWith('| ')) // table rows only
    .filter((l) => !/^\|\s*(Check\b|Domain\b|:?-{2,})/.test(l)) // drop headers + separators
    .length;
}

describe('README check count stays in sync with the registry', () => {
  const N = registeredCheckCount();
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

  it('registers a plausible number of checks', () => {
    expect(N).toBeGreaterThan(50);
  });

  it('headline "**N read-only checks**" matches the registry', () => {
    const nums = [...readme.matchAll(/\*\*(\d+) read-only checks\*\*/g)].map((m) => Number(m[1]));
    expect(nums.length).toBeGreaterThan(0); // the headline must exist
    for (const n of nums) {
      expect(n).toBe(N);
    }
  });

  it('"all N security checks" (usage) matches the registry', () => {
    const nums = [...readme.matchAll(/all (\d+) security checks/g)].map((m) => Number(m[1]));
    for (const n of nums) {
      expect(n).toBe(N);
    }
  });

  it('the "What It Checks" tables list exactly N checks', () => {
    expect(readmeTableRowCount(readme)).toBe(N);
  });
});
