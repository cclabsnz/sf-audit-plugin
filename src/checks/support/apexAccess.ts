import { testApexPattern } from '@cclabsnz/sf-core';

/**
 * How an Apex class's record sharing and CRUD/FLS are controlled (spec/apex-access-mode.md).
 *
 * Record sharing follows the class's own sharing keyword. WITH SYSTEM_MODE and
 * AccessLevel.SYSTEM_MODE switch off only CRUD/FLS for the operation they are on. A class with no
 * keyword runs with its caller's sharing, and as an entry point (Aura, REST, guest) without it.
 */
export type SharingKeyword = 'with' | 'without' | 'inherited' | 'none';

export const SYSTEM_MODE = /\bWITH\s+SYSTEM_MODE\b|\bAccessLevel\s*\.\s*SYSTEM_MODE\b/i;

/**
 * The body with comments removed. A class's keywords and access modes are read from code only:
 * a `without sharing` class with "with sharing" in a comment must not read as protected.
 * String literals are kept (dynamic SOQL carries WITH SYSTEM_MODE inside one), and scanned past
 * correctly, so `@RestResource(urlMapping='/x/*')` does not open a comment.
 */
export function apexCode(body: string): string {
  let out = '';
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    const next = body[i + 1];
    if (c === "'") {
      let j = i + 1;
      while (j < body.length && body[j] !== "'" && body[j] !== '\n') j += body[j] === '\\' ? 2 : 1;
      out += body.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && next === '/') {
      while (i < body.length && body[i] !== '\n') i++;
    } else if (c === '/' && next === '*') {
      const end = body.indexOf('*/', i + 2);
      out += ' ';
      i = end === -1 ? body.length : end + 2;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/** The code with string literals blanked, for matching declarations and enforcement that must not hide in text. */
export function codeWithoutStrings(body: string): string {
  return apexCode(body).replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
}

interface ClassDeclaration {
  name: string;
  /** The modifiers before `class`, from the previous statement or block boundary. */
  modifiers: string;
  /** The parent class named by `extends`, if any. */
  parent?: string;
}

/**
 * Every class declared in the body, outer and inner, found with literal patterns in one linear
 * pass (a regex built around the name backtracked badly on long runs of words).
 */
export function classDeclarations(body: string): ClassDeclaration[] {
  const code = codeWithoutStrings(body);
  const out: ClassDeclaration[] = [];
  const decl = /\bclass\s+(\w+)/gi;
  for (let m = decl.exec(code); m !== null; m = decl.exec(code)) {
    const start = Math.max(code.lastIndexOf(';', m.index), code.lastIndexOf('{', m.index), code.lastIndexOf('}', m.index)) + 1;
    const end = code.indexOf('{', m.index);
    const header = code.slice(m.index, end === -1 ? code.length : end);
    out.push({
      name: m[1],
      modifiers: code.slice(start, m.index).toLowerCase(),
      parent: /\bextends\s+([\w.]+)/i.exec(header)?.[1],
    });
  }
  return out;
}

function keywordOf(modifiers: string): SharingKeyword {
  if (/\bwithout\s+sharing\b/.test(modifiers)) return 'without';
  if (/\binherited\s+sharing\b/.test(modifiers)) return 'inherited';
  if (/\bwith\s+sharing\b/.test(modifiers)) return 'with';
  return 'none';
}

/**
 * The sharing keyword on the declaration of `className` itself, or null when the body declares no
 * class of that name (an interface, enum or trigger). Modifiers may sit on either side of the
 * keyword (`public virtual without sharing class`, `global with sharing virtual class`).
 */
export function sharingKeyword(className: string, body: string): SharingKeyword | null {
  const target = className.toLowerCase();
  const own = classDeclarations(body).find((d) => d.name.toLowerCase() === target);
  return own ? keywordOf(own.modifiers) : null;
}

/** The class `className` extends, as written in its declaration (namespace and outer class stripped). */
export function parentClass(className: string, body: string): string | undefined {
  const target = className.toLowerCase();
  const parent = classDeclarations(body).find((d) => d.name.toLowerCase() === target)?.parent;
  return parent?.split('.').pop();
}

/**
 * The sharing a class actually runs with. A class with no keyword takes its parent's when it
 * extends one: Apex classes inherit the sharing setting of the class they extend (spec MN-001).
 * `lookup` returns a class body by name; unknown parents leave the keyword as declared.
 */
export function effectiveSharing(className: string, body: string, lookup: (name: string) => string | undefined): SharingKeyword | null {
  let name = className;
  let current = body;
  const seen = new Set<string>();
  for (;;) {
    const keyword = sharingKeyword(name, current);
    if (keyword !== 'none') return keyword;
    const parent = parentClass(name, current);
    if (!parent || seen.has(parent.toLowerCase())) return keyword;
    seen.add(parent.toLowerCase());
    const parentBody = lookup(parent);
    if (parentBody === undefined) return keyword;
    name = parent;
    current = parentBody;
  }
}

/** Whether the class's code (not its comments) uses SYSTEM_MODE anywhere. */
export function usesSystemMode(body: string): boolean {
  const code = apexCode(body);
  return testApexPattern(code, SYSTEM_MODE) || testApexPattern(code, DML_AS_SYSTEM);
}

/**
 * Whether any class declared in the body, outer or inner, is `without sharing`. An inner class
 * keeps its own keyword, so a `with sharing` class can still run queries without sharing through
 * one (spec MN-002).
 */
export function declaresWithoutSharing(body: string): boolean {
  return classDeclarations(body).some((d) => keywordOf(d.modifiers) === 'without');
}

// Data-model access modes on DML: `insert as system rows;` / `update as user rows;`.
export const DML_AS_SYSTEM = /\b(?:insert|update|upsert|delete|undelete|merge)\s+as\s+system\b/i;
export const DML_AS_USER = /\b(?:insert|update|upsert|delete|undelete|merge)\s+as\s+user\b/i;

