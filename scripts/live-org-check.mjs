#!/usr/bin/env node
// Checks a full audit result from a live org you own against what that org is known to produce.
//
//   node scripts/live-org-check.mjs <report.json> <baseline.json>                  compare
//   node scripts/live-org-check.mjs <report.json> <baseline.json> --write-baseline record
//
// A check that filters on a value Salesforce never writes, or reads a field that does not exist,
// still "passes": only a known org shows it stopped finding what it used to. So this fails when:
//   - a check's query was rejected or the check crashed (an `<check>-error` finding);
//   - evidence coverage falls below the baseline's floor;
//   - a check goes unassessed that the baseline does not allow;
//   - any finding's status differs from the baseline (new, gone, or changed).
// Output is check and finding ids, statuses and counts only: never titles, detail or affected
// items, because CI logs on a public repository are public. Some finding ids embed org values
// (a user record id, a trusted-site domain, an agent's developer name), so an id that is not plain
// lowercase words is recorded as a short hash: stable across runs, but it names nothing.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const [reportPath, baselinePath, ...rest] = process.argv.slice(2);
if (!reportPath || !baselinePath) {
  console.error('usage: live-org-check.mjs <report.json> <baseline.json> [--write-baseline]');
  process.exit(2);
}
const write = rest.includes('--write-baseline');

const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
const result = raw.result ?? raw;
if (!Array.isArray(result.findings) || !result.coverage) {
  console.error('Not a full audit result: pass the JSON report from sf audit security --format json.');
  process.exit(2);
}

const status = (f) =>
  f.passed ? 'passed' : f.inconclusive || f.notAssessed ? 'inconclusive' : f.waived ? 'waived' : f.riskLevel === 'INFO' ? 'info' : `open:${f.riskLevel}`;
const safe = (id) => (/^[a-z0-9-]+$/.test(id) ? id : `#${createHash('sha256').update(String(id)).digest('hex').slice(0, 12)}`);
const observed = {};
const record = (k, s) => {
  // Two results with the same key are both kept: the second as k~2, and so on.
  let key = k, n = 1;
  while (key in observed) key = `${k}~${++n}`;
  observed[key] = s;
};
for (const f of result.findings) record(`${f.checkId}/${safe(f.id)}`, status(f));
// Attack chains too: a chain rule change shows up as a chain appearing, going or changing severity.
for (const c of result.attackChains ?? []) record(`chain/${safe(c.id)}`, `${c.confidence ?? 'named'}:${c.severity}`);
const notAssessed = [...(result.coverage.notAssessed ?? [])].sort();

let previous;
try {
  previous = JSON.parse(readFileSync(baselinePath, 'utf8'));
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
}

if (write) {
  const baseline = {
    // Two points below this run's coverage: a reviewed re-record moves the floor with the org.
    minCoverage: Math.max(0, result.coverage.percent - 2),
    allowUnassessed: notAssessed,
    findings: Object.fromEntries(Object.entries(observed).sort(([a], [b]) => a.localeCompare(b))),
  };
  writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n');
  console.log(`Baseline written: ${Object.keys(baseline.findings).length} findings, coverage floor ${baseline.minCoverage}%, ${notAssessed.length} allowed unassessed.`);
  process.exit(0);
}

if (!previous) {
  console.error(`No baseline at ${baselinePath}. Record one with --write-baseline from a run you have reviewed.`);
  process.exit(2);
}

const problems = [];
const errors = result.findings.filter((f) => f.id === `${f.checkId}-error` && !/insufficient permissions/.test(f.title ?? ''));
for (const f of errors) problems.push(`check failed or its query was rejected: ${f.checkId}`);
if (result.coverage.percent < previous.minCoverage) problems.push(`coverage ${result.coverage.percent}% is below the ${previous.minCoverage}% floor`);
for (const id of notAssessed) if (!(previous.allowUnassessed ?? []).includes(id)) problems.push(`not assessed: ${id}`);

const drift = [];
for (const [k, s] of Object.entries(observed)) {
  const was = previous.findings[k];
  if (was === undefined) drift.push(`new        ${k}: ${s}`);
  else if (was !== s) drift.push(`changed    ${k}: ${was} -> ${s}`);
}
for (const [k, was] of Object.entries(previous.findings)) if (!(k in observed)) drift.push(`gone       ${k}: was ${was}`);

console.log(`## Live org verification\n`);
console.log(`Findings: ${Object.keys(observed).length}. Coverage: ${result.coverage.percent}% (floor ${previous.minCoverage}%). Grade ${result.grade}.\n`);
if (problems.length) console.log(['### Problems', '', ...problems.map((p) => `- ${p}`), ''].join('\n'));
if (drift.length) {
  console.log(['### Drift from the baseline', '', '```', ...drift, '```', ''].join('\n'));
  console.log('If a change is intended (a check was fixed or the org changed), re-record the baseline with --write-baseline and commit it.');
}
if (!problems.length && !drift.length) console.log('Every finding matches the baseline.');
process.exit(problems.length || drift.length ? 1 : 0);
