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

/** The code with string literals blanked, for matching declarations that must not hide in text. */
function codeWithoutStrings(body: string): string {
  return apexCode(body).replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The sharing keyword on the declaration of `className` itself, or null when the body declares no
 * class of that name (an interface, enum or trigger). Modifiers may sit on either side of the
 * keyword (`public virtual without sharing class`, `global with sharing virtual class`).
 */
export function sharingKeyword(className: string, body: string): SharingKeyword | null {
  const code = codeWithoutStrings(body);
  const decl = new RegExp(`((?:\\b\\w+\\s+)*?)class\\s+${escapeRe(className)}\\b`, 'i');
  const m = decl.exec(code);
  if (!m) return null;
  const modifiers = m[1].toLowerCase();
  if (/\bwithout\s+sharing\b/.test(modifiers)) return 'without';
  if (/\binherited\s+sharing\b/.test(modifiers)) return 'inherited';
  if (/\bwith\s+sharing\b/.test(modifiers)) return 'with';
  return 'none';
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
  return /\bwithout\s+sharing\s+(?:\w+\s+)*?class\b/i.test(codeWithoutStrings(body));
}

// Data-model access modes on DML: `insert as system rows;` / `update as user rows;`.
export const DML_AS_SYSTEM = /\b(?:insert|update|upsert|delete|undelete|merge)\s+as\s+system\b/i;
export const DML_AS_USER = /\b(?:insert|update|upsert|delete|undelete|merge)\s+as\s+user\b/i;

