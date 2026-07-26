import type { CouplingOperation } from '../types.js';

/**
 * Body-regex fallback for uncompiled Apex (empty SymbolTable). Extracts object references and
 * their operations from SOQL FROM clauses, `new` instantiations, and DML statements whose
 * target variable type is resolvable from a local declaration. Deliberately approximate —
 * only objects in the `known` set are kept, to suppress relationship-name false positives.
 */
export function regexAnalyze(body: string, known: Set<string>): Map<string, Set<CouplingOperation>> {
  const map = new Map<string, Set<CouplingOperation>>();

  // SOQL: FROM <Object>  -> read
  for (const m of body.matchAll(/\bfrom\s+([A-Za-z0-9_]+)/gi)) {
    if (known.has(m[1])) add(map, m[1], 'read');
  }

  // Local declarations -> variable type map (Type var; / Type var = ; / List<Type> var).
  const varType = new Map<string, string>();
  for (const m of body.matchAll(/\b([A-Za-z][A-Za-z0-9_]*(?:__c)?)\s+([a-zA-Z_]\w*)\s*[=;]/g)) {
    if (known.has(m[1])) varType.set(m[2], m[1]);
  }
  for (const m of body.matchAll(/\bList\s*<\s*([A-Za-z][A-Za-z0-9_]*(?:__c)?)\s*>\s+([a-zA-Z_]\w*)/gi)) {
    if (known.has(m[1])) varType.set(m[2], m[1]);
  }

  // new <Object>(...) -> create
  for (const m of body.matchAll(/\bnew\s+([A-Za-z][A-Za-z0-9_]*(?:__c)?)\s*[([]/g)) {
    if (known.has(m[1])) add(map, m[1], 'create');
  }

  // DML keyword + variable, and Database.<dml>(variable)
  const dml = /\b(insert|update|delete|upsert|merge)\s+([a-zA-Z_]\w*)/gi;
  const dbDml = /\bDatabase\.(insert|update|delete|upsert|merge)\w*\s*\(\s*([a-zA-Z_]\w*)/gi;
  for (const re of [dml, dbDml]) {
    for (const m of body.matchAll(re)) {
      const type = varType.get(m[2]);
      if (type) add(map, type, dmlOperation(m[1].toLowerCase()));
    }
  }

  return map;
}

function dmlOperation(keyword: string): CouplingOperation {
  switch (keyword) {
    case 'insert':
      return 'create';
    case 'delete':
      return 'delete';
    default:
      return 'update'; // update, upsert, merge
  }
}

function add(map: Map<string, Set<CouplingOperation>>, obj: string, op: CouplingOperation): void {
  const set = map.get(obj) ?? new Set<CouplingOperation>();
  set.add(op);
  map.set(obj, set);
}
