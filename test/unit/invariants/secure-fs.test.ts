import { join } from 'node:path';
import {
  SECURE_FS_RULES,
  findInvariantViolations,
  formatViolations,
} from '@cclabsnz/sf-core/testing';

/**
 * Secure filesystem invariant guard for @cclabsnz/sf-audit.
 *
 * Local sensitive data (~/.sf/audit-history, ~/.sf/incidents, ~/.sf/event-baseline) must be
 * created with 0700 permissions for directories and 0600 permissions for files to ensure
 * other unprivileged local users or processes cannot read org vulnerability maps or forensic logs.
 *
 * All persistent store operations must use `secureFs` from `@cclabsnz/sf-core`.
 */

const SRC_DIR = join(process.cwd(), 'src');

describe('secure-fs invariant (sf-audit)', () => {
  it('forbids raw un-moded filesystem writes outside secureFs', () => {
    const violations = findInvariantViolations(SRC_DIR, SECURE_FS_RULES);
    if (violations.length > 0) {
      throw new Error(
        'Secure-fs invariant violated — persistent local store writes must use secureFs:\n' +
          formatViolations(violations) +
          '\n\nAll writes to ~/.sf/ directories must enforce 0700 on directories and 0600 on files. ' +
          'Use `secureFs.mkdirSync`, `secureFs.writeFileSync`, or `secureFs.createWriteStream`. ' +
          'If this is a false positive for user-facing report destinations, add an `// invariant:allow` comment on the line after review.',
      );
    }
  });
});
