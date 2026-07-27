import { join } from 'node:path';
import {
  ORG_WRITE_RULES,
  collectSourceFiles,
  filesUsingFetch,
  findInvariantViolations,
  formatViolations,
} from '@cclabsnz/sf-core/testing';

/**
 * Read-only invariant guard for @cclabsnz/sf-orgintel.
 *
 * The product promise is that this plugin is *strictly read-only*: SOQL / Tooling /
 * REST GET queries and Metadata reads only, never a mutation of the org it is pointed at.
 * This turns that promise into an enforced CI gate rather than a README claim.
 *
 * The scan runs against this package's own `src/` — the checks and their inlined SOQL
 * live here, not in core, so this is where the guarantee has to bite.
 */

const SRC_DIR = join(process.cwd(), 'src');

describe('read-only invariant (sf-orgintel)', () => {
  it('scans a non-trivial number of source files', () => {
    // Guards against the scan silently matching nothing and the suite passing vacuously.
    expect(collectSourceFiles(SRC_DIR).length).toBeGreaterThan(30);
  });

  it('contains no org-mutating API calls anywhere in src/', () => {
    const violations = findInvariantViolations(SRC_DIR, ORG_WRITE_RULES);
    if (violations.length > 0) {
      throw new Error(
        'Read-only invariant violated — the following look like org writes:\n' +
          formatViolations(violations) +
          '\n\nThis plugin must never mutate a target org. If this is a false positive, ' +
          'add an `// invariant:allow` comment on the line after review.',
      );
    }
  });

  it('performs no direct fetch() — all org I/O funnels through the core clients', () => {
    expect(filesUsingFetch(SRC_DIR)).toEqual([]);
  });
});
