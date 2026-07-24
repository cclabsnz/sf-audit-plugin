import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * Read-only invariant guard.
 *
 * The entire product promise of sf-audit is that it is *strictly read-only*: it issues
 * only SOQL / Tooling / REST GET queries and Metadata API reads, and never mutates the
 * org it is pointed at. This test turns that promise into an enforced CI gate so it can
 * be trusted, not just asserted in a README.
 *
 * It statically scans every source file for tokens that would indicate a write path —
 * jsforce mutation APIs, HTTP write verbs, and bulk/composite write jobs. If any appear,
 * CI fails. The patterns are deliberately chosen to match Salesforce/jsforce write APIs
 * and HTTP verbs (which have no collision with JS built-ins like Map#delete or
 * Object.create), so a green result is meaningful rather than merely passing.
 *
 * All org I/O funnels through src/api/*ClientImpl.ts (RestClient = GET only, SoqlClient
 * and ToolingClient = query only, MetadataClient = read only). A second assertion pins
 * that boundary: `fetch()` may appear only in the REST client, and never with a method.
 */

const SRC_DIR = join(process.cwd(), 'src');

/** Mutating tokens that must never appear in source. Each entry: [label, regex]. */
const FORBIDDEN: Array<[string, RegExp]> = [
  // HTTP write verbs on any request/fetch options object.
  ['HTTP write verb (method: POST/PUT/PATCH/DELETE)', /method\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)['"`]/i],
  // jsforce SObject writes: conn.sobject('X').create(...) / .update / .insert / .upsert / .destroy / .delete
  ['jsforce SObject write', /\.sobject\([^)]*\)\s*\.\s*(?:create|update|insert|upsert|destroy|delete)\b/i],
  // jsforce writes invoked directly on a connection-like receiver (conn, connection, this.conn ...).
  ['jsforce connection write', /\bconn(?:ection)?\s*\.\s*(?:create|update|insert|upsert|destroy|delete)\b/i],
  // Metadata API mutations.
  ['Metadata API write', /\.\s*metadata\s*\.\s*(?:create|update|upsert|delete|rename|deploy)\b/i],
  // Tooling API mutations.
  ['Tooling API write', /\.\s*tooling\s*\.\s*(?:create|update|upsert|destroy|delete)\b/i],
  // Bulk / Bulk2 are write-capable job APIs; a read-only tool has no reason to touch them.
  ['Bulk API job', /\.\s*bulk2?\s*\./i],
  // Composite write graphs.
  ['Composite write graph', /\.\s*(?:compositeGraph|createBatch|createJob)\b/i],
];

/** `fetch()` is allowed only in this file, and only as a GET (no method option). */
const FETCH_ALLOWLIST = ['api/RestClientImpl.ts'];

function collectSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...collectSourceFiles(full));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

describe('read-only invariant', () => {
  const files = collectSourceFiles(SRC_DIR);

  it('scans a non-trivial number of source files', () => {
    // Guards against the glob silently matching nothing and the test passing vacuously.
    expect(files.length).toBeGreaterThan(20);
  });

  it('contains no org-mutating API calls anywhere in src/', () => {
    const violations: string[] = [];
    for (const file of files) {
      const rel = relative(SRC_DIR, file);
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        // Allow an explicit, reviewed escape hatch on a per-line basis.
        if (line.includes('readonly-invariant:allow')) return;
        for (const [label, pattern] of FORBIDDEN) {
          if (pattern.test(line)) {
            violations.push(`${rel}:${i + 1}  [${label}]  ${line.trim()}`);
          }
        }
      });
    }
    if (violations.length > 0) {
      throw new Error(
        'Read-only invariant violated — the following look like org writes:\n' +
          violations.join('\n') +
          '\n\nsf-audit must never mutate a target org. If this is a false positive, ' +
          'add a `// readonly-invariant:allow` comment on the line after review.'
      );
    }
  });

  it('uses fetch() only in the allowlisted REST client, and only as a GET', () => {
    for (const file of files) {
      const rel = relative(SRC_DIR, file).split('\\').join('/');
      const src = readFileSync(file, 'utf8');
      if (!/\bfetch\s*\(/.test(src)) continue;
      expect(FETCH_ALLOWLIST).toContain(rel);
      // The one allowed fetch must not carry a method option (default = GET).
      expect(/fetch\s*\([^;]*method\s*:/is.test(src)).toBe(false);
    }
  });
});
