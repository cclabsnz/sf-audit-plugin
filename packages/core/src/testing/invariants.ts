import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * Shared static-analysis guards behind the two promises every CloudCounsel plugin makes:
 * it never writes to your org, and nothing it produces phones home.
 *
 * These live in core, and each package runs them against its OWN `src/`, so a package
 * cannot silently opt out by forgetting to register somewhere central — and a violation
 * fails the build of the package that introduced it.
 *
 * Both guards are deliberately token-based rather than type-aware: a green result means
 * the forbidden shape does not appear anywhere in source, which is a claim a sceptical
 * reader can re-derive with grep. Patterns avoid collisions with JS built-ins (Map#delete,
 * Object.create) so passing is meaningful rather than merely quiet.
 */

/** One offending source line. */
export interface InvariantViolation {
  /** Path relative to the scanned `src/`. */
  file: string;
  /** 1-indexed line number. */
  line: number;
  /** Human-readable rule label. */
  rule: string;
  /** The offending line, trimmed. */
  snippet: string;
}

export type InvariantRule = readonly [label: string, pattern: RegExp];

/**
 * Org-mutation tokens. Every CloudCounsel plugin is strictly read-only: SOQL / Tooling /
 * REST GET / Metadata reads only.
 */
export const ORG_WRITE_RULES: readonly InvariantRule[] = [
  ['HTTP write verb (method: POST/PUT/PATCH/DELETE)', /method\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)['"`]/i],
  ['jsforce SObject write', /\.sobject\([^)]*\)\s*\.\s*(?:create|update|insert|upsert|destroy|delete)\b/i],
  ['jsforce connection write', /\bconn(?:ection)?\s*\.\s*(?:create|update|insert|upsert|destroy|delete)\b/i],
  ['Metadata API write', /\.\s*metadata\s*\.\s*(?:create|update|upsert|delete|rename|deploy)\b/i],
  ['Tooling API write', /\.\s*tooling\s*\.\s*(?:create|update|upsert|destroy|delete)\b/i],
  ['Bulk API job', /\.\s*bulk2?\s*\./i],
  ['Composite write graph', /\.\s*(?:compositeGraph|createBatch|createJob)\b/i],
] as const;

/**
 * Network-egress tokens. The only network destination these tools may contact is the
 * Salesforce org the operator authenticated against — via the core REST/SOQL/Tooling
 * clients. No telemetry, no analytics, no LLM calls, and no remote assets in generated
 * reports (an audit report carries sensitive findings and is often opened offline, so it
 * must not fetch script, styles or fonts from a third party when a client opens it).
 */
export const NETWORK_EGRESS_RULES: readonly InvariantRule[] = [
  [
    'remote asset in generated HTML (<script src>/<link href>/@import)',
    /<script[^>]+src\s*=\s*["'`]?\s*https?:|<link[^>]+href\s*=\s*["'`]?\s*https?:|@import\s+url\(\s*["']?https?:/i,
  ],
  [
    'third-party HTTP client',
    /(?:from\s+|require\()\s*['"](?:axios|got|node-fetch|undici|superagent|request|phin|ky)['"]/i,
  ],
  ['raw node http/https module', /(?:from\s+|require\()\s*['"](?:node:)?https?['"]/i],
  [
    'telemetry / analytics / LLM endpoint',
    /api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|sentry\.io|segment\.(?:io|com)|posthog\.com|mixpanel\.com|google-analytics\.com|amplitude\.com/i,
  ],
  ['websocket client', /\bnew\s+WebSocket\s*\(|(?:from\s+|require\()\s*['"]ws['"]/i],
] as const;

/** Recursively collect `.ts` source files (excluding declaration files) under `dir`. */
export function collectSourceFiles(dir: string): string[] {
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

/**
 * Scan every source file under `srcDir` for lines matching any rule.
 *
 * A line carrying an `invariant:allow` comment is skipped, so a reviewed false positive
 * has an explicit, greppable escape hatch rather than forcing the rule to be weakened.
 * The legacy `readonly-invariant:allow` spelling is honoured too.
 */
export function findInvariantViolations(
  srcDir: string,
  rules: readonly InvariantRule[],
): InvariantViolation[] {
  const violations: InvariantViolation[] = [];
  for (const file of collectSourceFiles(srcDir)) {
    const rel = relative(srcDir, file).split('\\').join('/');
    readFileSync(file, 'utf8')
      .split('\n')
      .forEach((line, i) => {
        if (line.includes('invariant:allow')) return;
        for (const [rule, pattern] of rules) {
          if (pattern.test(line)) {
            violations.push({ file: rel, line: i + 1, rule, snippet: line.trim() });
          }
        }
      });
  }
  return violations;
}

/** Render violations as a reviewable multi-line report. */
export function formatViolations(violations: readonly InvariantViolation[]): string {
  return violations.map((v) => `${v.file}:${v.line}  [${v.rule}]  ${v.snippet}`).join('\n');
}

const FETCH_CALL = /\bfetch\s*\(/;

/**
 * Source files under `srcDir` that call the global fetch, as `src`-relative paths.
 *
 * Scanned line-by-line rather than whole-file so the `invariant:allow` escape hatch works
 * here too — otherwise a doc comment mentioning the call by name would be indistinguishable
 * from a real call site.
 */
export function filesUsingFetch(srcDir: string): string[] {
  const hits: string[] = [];
  for (const file of collectSourceFiles(srcDir)) {
    const lines = readFileSync(file, 'utf8').split('\n');
    const calls = lines.some((line) => !line.includes('invariant:allow') && FETCH_CALL.test(line));
    if (calls) hits.push(relative(srcDir, file).split('\\').join('/'));
  }
  return hits;
}

/** True if any fetch call in the file carries an explicit `method:` option (i.e. is not a GET). */
export function fetchUsesNonGetMethod(file: string): boolean {
  return /fetch\s*\([^;]*method\s*:/is.test(readFileSync(file, 'utf8'));
}
