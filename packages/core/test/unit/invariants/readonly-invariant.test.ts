import { join } from 'node:path';
import {
  ORG_WRITE_RULES,
  collectSourceFiles,
  fetchUsesNonGetMethod,
  filesUsingFetch,
  findInvariantViolations,
  formatViolations,
} from '../../../src/testing/invariants.js';

/**
 * Read-only invariant guard for @cclabsnz/sf-core.
 *
 * The product promise is that these tools are *strictly read-only*: SOQL / Tooling /
 * REST GET queries and Metadata reads only, never a mutation of the org they are pointed
 * at. This turns that promise into an enforced CI gate rather than a README claim.
 *
 * Each package runs this against its own `src/`, so no package can opt out by omission.
 */

const SRC_DIR = join(process.cwd(), 'src');

/** `fetch()` is allowed only here, and only as a GET. All org I/O funnels through it. */
const FETCH_ALLOWLIST = ['api/RestClientImpl.ts'];

describe('read-only invariant (core)', () => {
  it('scans a non-trivial number of source files', () => {
    // Guards against the scan silently matching nothing and the suite passing vacuously.
    expect(collectSourceFiles(SRC_DIR).length).toBeGreaterThan(20);
  });

  it('contains no org-mutating API calls anywhere in src/', () => {
    const violations = findInvariantViolations(SRC_DIR, ORG_WRITE_RULES);
    if (violations.length > 0) {
      throw new Error(
        'Read-only invariant violated — the following look like org writes:\n' +
          formatViolations(violations) +
          '\n\nThese tools must never mutate a target org. If this is a false positive, ' +
          'add an `// invariant:allow` comment on the line after review.',
      );
    }
  });

  it('uses fetch() only in the allowlisted REST client, and only as a GET', () => {
    for (const rel of filesUsingFetch(SRC_DIR)) {
      expect(FETCH_ALLOWLIST).toContain(rel);
      expect(fetchUsesNonGetMethod(join(SRC_DIR, rel))).toBe(false);
    }
  });
});
