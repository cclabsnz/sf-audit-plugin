// An AuditContext that answers like a real org with the captured Developer Edition schema
// (test/fixtures/schema/developer-edition.json, from scripts/capture-schema.mjs).
//
// Every query is checked the way Salesforce checks it: the object must be served by the API the
// query is sent to, selected and filtered fields must exist, filtered fields must be filterable,
// aggregated fields aggregatable, and only aggregates may carry an alias (never expr0..n).
// A query that fails is recorded as a violation and rejected with the error Salesforce would
// return, so the check under test sees exactly what it would see on a live org. Queries that pass
// return no rows.
import { readFileSync } from 'node:fs';
import type { AuditContext } from '@cclabsnz/sf-core';

type FieldInfo = { filterable: boolean; aggregatable: boolean; type: string; relationship?: { name: string; to: string[] }; values?: string[] };
type Api = 'soql' | 'tooling';
type Schema = { apiVersion: string; soql: Record<string, Record<string, FieldInfo>>; tooling: Record<string, Record<string, FieldInfo>> };

export const SCHEMA: Schema = JSON.parse(
  readFileSync(new URL('../../../fixtures/schema/developer-edition.json', import.meta.url), 'utf8'),
);

export interface Violation {
  api: Api;
  query: string;
  error: string;
}

/** True when the object exists in neither API: a feature this edition lacks, not a wrong query. */
export function absentEverywhere(object: string): boolean {
  return !(object in SCHEMA.soql) && !(object in SCHEMA.tooling);
}

function apiError(errorCode: string, message: string): Error {
  return Object.assign(new Error(message), { errorCode, name: errorCode });
}

/** Split on commas at parenthesis depth 0. */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Replace each parenthesised `(SELECT ...)` with a placeholder, returning the inner queries. */
function extractSubqueries(q: string): { outer: string; subs: string[] } {
  const subs: string[] = [];
  let outer = '';
  let i = 0;
  while (i < q.length) {
    if (q[i] === '(' && /^\(\s*SELECT\b/i.test(q.slice(i))) {
      let depth = 0;
      let j = i;
      for (; j < q.length; j++) {
        if (q[j] === '(') depth++;
        if (q[j] === ')' && --depth === 0) break;
      }
      subs.push(q.slice(i + 1, j));
      outer += `(__SUB${subs.length - 1}__)`;
      i = j + 1;
    } else outer += q[i++];
  }
  return { outer, subs };
}

const CLAUSE_END = /\b(WHERE|WITH|GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET|FOR\s+(VIEW|REFERENCE|UPDATE)|ALL\s+ROWS|USING\s+SCOPE)\b/i;
const IDENT = /^[A-Za-z][A-Za-z0-9_]*$/;
const AGG = /^(COUNT|COUNT_DISTINCT|SUM|AVG|MIN|MAX|CALENDAR_\w+|DAY_\w+|FISCAL_\w+|HOUR_\w+|WEEK_\w+)\s*\(\s*([^)]*)\s*\)(?:\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*))?$/i;

/**
 * Resolve a field path such as `Assignee.Profile.Name` from `object`, hop by hop through lookup
 * relationships. Returns the final field, or null when a hop lands on an object the snapshot does
 * not hold (then nothing can be said). Throws as Salesforce would for an unknown hop or field.
 */
function resolvePath(api: Api, object: string, path: string): FieldInfo | null {
  const [head, ...rest] = path.split('.');
  const fields = SCHEMA[api][object];
  if (!fields) return null;
  if (rest.length === 0) {
    const f = fields[head];
    if (!f) throw apiError('INVALID_FIELD', `No such column '${head}' on entity '${object}'.`);
    return f;
  }
  const lookup = Object.values(fields).find((f) => f.relationship?.name === head);
  if (!lookup) throw apiError('INVALID_FIELD', `Didn't understand relationship '${head}' in field path. (on entity '${object}')`);
  // Polymorphic lookups: the path is valid if any target the snapshot knows carries it.
  const known = lookup.relationship!.to.filter((t) => SCHEMA[api][t]);
  if (known.length === 0) return null;
  let lastError: unknown;
  for (const target of known) {
    try {
      return resolvePath(api, target, rest.join('.'));
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

const PATH = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

/** Validate one SELECT statement (no outer parentheses). Throws as Salesforce would. */
export function validate(api: Api, query: string, childContext = false): void {
  const q = query.replace(/\s+/g, ' ').trim();
  const { outer, subs } = extractSubqueries(q);
  const m = /^SELECT (.+?) FROM ([A-Za-z0-9_]+)(.*)$/i.exec(outer);
  if (!m) return; // not a shape this validator understands; let it pass
  const [, selectList, object, tail] = m;

  if (childContext) {
    // A select-list subquery names a child relationship, not an object; skip it.
    return;
  }
  const fields = SCHEMA[api][object];
  if (!fields) {
    throw apiError('INVALID_TYPE', `sObject type '${object}' is not supported.`);
  }

  for (const raw of splitTop(selectList)) {
    const item = raw.trim();
    if (/^\(__SUB\d+__\)$/.test(item)) continue;
    if (/^TYPEOF\b/i.test(item)) continue;
    const agg = AGG.exec(item);
    if (agg) {
      const [, fn, arg, alias] = agg;
      if (alias && /^expr\d+$/i.test(alias)) throw apiError('MALFORMED_QUERY', `alias is reserved: ${alias}`);
      if (fn.toUpperCase() === 'COUNT' && arg === '') continue;
      if (IDENT.test(arg)) {
        const f = fields[arg];
        if (!f) throw apiError('INVALID_FIELD', `No such column '${arg}' on entity '${object}'.`);
        if (!f.aggregatable) throw apiError('MALFORMED_QUERY', `field ${arg} does not support aggregate operator ${fn.toUpperCase()}`);
      }
      continue;
    }
    const parts = item.split(/\s+/);
    if (parts.length > 1) {
      if (/^(FORMAT|toLabel|convertCurrency|GROUPING)\s*\(/i.test(item)) continue;
      // A grouped field may carry an alias; any other plain field may not.
      if (!/\bGROUP\s+BY\b/i.test(tail)) throw apiError('MALFORMED_QUERY', 'only aggregate expressions use field aliasing');
      if (/^expr\d+$/i.test(parts[parts.length - 1])) throw apiError('MALFORMED_QUERY', `alias is reserved: ${parts[parts.length - 1]}`);
      continue;
    }
    if (IDENT.test(item) && !fields[item]) {
      throw apiError('INVALID_FIELD', `No such column '${item}' on entity '${object}'.`);
    }
    if (PATH.test(item)) resolvePath(api, object, item);
  }

  const where = /\bWHERE\b(.*)/i.exec(tail);
  if (where) {
    const body = where[1].split(CLAUSE_END)[0] ?? '';
    const condRe = /(?:^|[\s(])([A-Za-z][A-Za-z0-9_.]*)\s*(=|!=|<>|<=|>=|<|>|\bLIKE\b|\bNOT\s+IN\b|\bIN\b|\bINCLUDES\b|\bEXCLUDES\b)/gi;
    for (const c of body.matchAll(condRe)) {
      const name = c[1];
      if (/^(AND|OR|NOT)$/i.test(name)) continue;
      const f = resolvePath(api, object, name);
      if (f && !f.filterable) throw apiError('INVALID_FIELD', `field '${name.split('.').pop()}' can not be filtered in a query call`);
    }
    // A picklist compared with a value it does not have is accepted by the org and matches nothing,
    // silently (RowCause = 'SharingRule' hid every sharing rule). Not an org error: a guard of ours.
    // Describe does not list every value a system picklist holds: a live org has Group.Type
    // 'GuestUserGroup' and 'ManagedContentSpaceRole', which its describe omits.
    // Keyed by value, not path, so a relationship path (Group.Type from GroupMember) is covered too.
    const SEEN_LIVE = new Set(['guestusergroup', 'managedcontentspacerole']);
    const literalCond = /(?:^|[\s(])([A-Za-z][A-Za-z0-9_.]*)\s*(=|!=|<>|\bNOT\s+IN\b|\bIN\b)\s*(\((?!\s*__SUB)[^)]*\)|'(?:[^'\\]|\\.)*')/gi;
    for (const c of body.matchAll(literalCond)) {
      const f = resolvePath(api, object, c[1]);
      if (!f?.values) continue;
      for (const lit of c[3].matchAll(/'((?:[^'\\]|\\.)*)'/g)) {
        // SOQL compares picklist values without regard to case.
        const value = lit[1].toLowerCase();
        if (!f.values.some((v) => v.toLowerCase() === value) && !SEEN_LIVE.has(value)) {
          throw apiError('UNKNOWN_PICKLIST_VALUE', `'${lit[1]}' is not a value of picklist ${object}.${c[1]}: the filter matches nothing`);
        }
      }
    }
  }

  // Semi-join subqueries in WHERE name real objects; select-list subqueries name relationships.
  const selectSubs = new Set([...selectList.matchAll(/__SUB(\d+)__/g)].map((x) => Number(x[1])));
  subs.forEach((sub, i) => validate(api, sub, selectSubs.has(i)));
}

/** Rows a valid query returns; undefined or none means no rows. A COUNT() query's totalSize is the row count. */
export type RowSource = (api: Api, query: string) => unknown[] | undefined;

/**
 * A fresh context plus the violations it records. Objects absent from both APIs are rejected like
 * a real org rejects them, but are not recorded: an edition lacking a feature is not a check bug.
 * `rows` seeds answers to valid queries, so a check goes past its first empty result and its
 * deeper queries are validated too; every query sent is kept in `queries`.
 */
export function schemaCtx(rows: RowSource = () => undefined): { ctx: AuditContext; violations: Violation[]; queries: Violation[] } {
  const violations: Violation[] = [];
  const queries: Violation[] = [];
  const run = (api: Api, query: string): unknown[] => {
    queries.push({ api, query: query.replace(/\s+/g, ' ').trim(), error: '' });
    try {
      validate(api, query);
    } catch (err) {
      const object = /\bFROM\s+([A-Za-z0-9_]+)/i.exec(query)?.[1] ?? '';
      const msg = (err as Error).message;
      const absent = msg.includes('is not supported') && absentEverywhere(object);
      if (!absent) violations.push({ api, query: query.replace(/\s+/g, ' ').trim(), error: msg });
      throw err;
    }
    return rows(api, query.replace(/\s+/g, ' ').trim()) ?? [];
  };
  const describe = (api: Api, path: string) => {
    const obj = /sobjects\/([A-Za-z0-9_]+)\/describe/.exec(path)?.[1];
    const fields = obj ? SCHEMA[api][obj] : undefined;
    if (!fields) return Promise.reject(apiError('NOT_FOUND', `The requested resource does not exist`));
    return Promise.resolve({
      name: obj,
      fields: Object.entries(fields).map(([name, f]) => ({ name, ...f })),
    });
  };
  const ctx: AuditContext = {
    soql: {
      query: async (q: string) => {
        const records = run('soql', q);
        return { records, totalSize: records.length, done: true } as any;
      },
      queryAll: async (q: string) => run('soql', q),
    } as any,
    tooling: {
      query: async (q: string) => run('tooling', q),
      getRecord: () => Promise.reject(apiError('NOT_FOUND', 'not found')),
    } as any,
    rest: {
      get: (path: string) => {
        if (/^\/?tooling\/sobjects\/[^/]+\/describe/.test(path)) return describe('tooling', path);
        if (/^\/?sobjects\/[^/]+\/describe/.test(path)) return describe('soql', path);
        return Promise.resolve({});
      },
      getRaw: () => Promise.resolve(''),
      getRawToFile: () => Promise.resolve(0),
    } as any,
    orgInfo: { id: '00Dxx0000000000EAA', name: 'Schema Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
    cache: {},
  };
  return { ctx, violations, queries };
}
