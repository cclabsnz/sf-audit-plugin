import { join } from 'node:path';
import {
  NETWORK_EGRESS_RULES,
  findInvariantViolations,
  formatViolations,
} from '../../../src/testing/invariants.js';

/**
 * Network-egress invariant guard for @cclabsnz/sf-core.
 *
 * The stated promise is local-first: the only network destination is the Salesforce org
 * the operator authenticated against. No telemetry, no analytics, no LLM calls — and no
 * remote assets in generated reports, which carry sensitive findings and are routinely
 * opened offline or on locked-down analyst machines.
 *
 * This is the guard that would have caught the CDN-hosted Chart.js and Google Fonts
 * references that previously shipped in the HTML renderers.
 */

const SRC_DIR = join(process.cwd(), 'src');

describe('network-egress invariant (core)', () => {
  it('makes no network calls beyond the authenticated org', () => {
    const violations = findInvariantViolations(SRC_DIR, NETWORK_EGRESS_RULES);
    if (violations.length > 0) {
      throw new Error(
        'Network-egress invariant violated — the following would contact a third party:\n' +
          formatViolations(violations) +
          '\n\nThese tools are local-first: the only permitted destination is the org the ' +
          'operator authenticated against, and generated reports must be fully self-contained. ' +
          'If this is a false positive, add an `// invariant:allow` comment on the line after review.',
      );
    }
  });
});
