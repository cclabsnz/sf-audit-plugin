#!/usr/bin/env node
// Compares two schema snapshots from scripts/capture-schema.mjs: the committed fixture the query
// guard uses, and a fresh capture from the same Developer Edition org. A Salesforce release that
// adds, removes or retypes a field, or changes a picklist's values, makes the guard's verdicts stale.
//
//   node scripts/schema-drift.mjs <committed.json> <fresh.json>
//
// Prints standard object and field names only (the snapshots hold nothing else) and exits 1 on drift.
import { readFileSync } from 'node:fs';

const [aPath, bPath] = process.argv.slice(2);
if (!aPath || !bPath) {
  console.error('usage: schema-drift.mjs <committed.json> <fresh.json>');
  process.exit(2);
}
const a = JSON.parse(readFileSync(aPath, 'utf8'));
const b = JSON.parse(readFileSync(bPath, 'utf8'));
const fieldsOf = (o) => (o && typeof o === 'object' ? (o.fields ?? o) : {});
const out = [];
if (a.apiVersion !== b.apiVersion) out.push(`API version ${a.apiVersion} -> ${b.apiVersion}`);

for (const api of new Set([...Object.keys(a), ...Object.keys(b)])) {
  const A = a[api] ?? {}, B = b[api] ?? {};
  if (typeof A !== 'object' || typeof B !== 'object') continue;
  for (const obj of new Set([...Object.keys(A), ...Object.keys(B)])) {
    if (!(obj in B)) { out.push(`${api} ${obj}: no longer served`); continue; }
    if (!(obj in A)) { out.push(`${api} ${obj}: newly served`); continue; }
    const FA = fieldsOf(A[obj]), FB = fieldsOf(B[obj]);
    for (const f of new Set([...Object.keys(FA), ...Object.keys(FB)])) {
      const x = FA[f], y = FB[f];
      if (!y) { out.push(`${api} ${obj}.${f}: removed`); continue; }
      if (!x) { out.push(`${api} ${obj}.${f}: added`); continue; }
      for (const prop of ['type', 'filterable', 'aggregatable']) if (x[prop] !== y[prop]) out.push(`${api} ${obj}.${f}: ${prop} ${x[prop]} -> ${y[prop]}`);
      const va = new Set(x.values ?? []), vb = new Set(y.values ?? []);
      const gone = [...va].filter((v) => !vb.has(v)), added = [...vb].filter((v) => !va.has(v));
      if (gone.length) out.push(`${api} ${obj}.${f}: picklist values removed: ${gone.join(', ')}`);
      if (added.length) out.push(`${api} ${obj}.${f}: picklist values added: ${added.join(', ')}`);
    }
  }
}

if (out.length === 0) {
  console.log('Schema matches the committed snapshot.');
  process.exit(0);
}
console.log(['## Schema drift', '', 'The org schema differs from test/fixtures/schema/developer-edition.json. Re-capture it with scripts/capture-schema.mjs, run the tests, and fix any check the schema guard now rejects.', '', '```', ...out.sort(), '```'].join('\n'));
process.exit(1);
