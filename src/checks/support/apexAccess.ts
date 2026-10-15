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
 * String literals are kept, since dynamic SOQL carries WITH SYSTEM_MODE inside one.
 */
export function apexCode(body: string): string {
  return body.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The sharing keyword on the declaration of `className` itself, or null when the body declares no
 * class of that name (an interface, enum or trigger). Modifiers may sit on either side of the
 * keyword (`public virtual without sharing class`, `global with sharing virtual class`).
 */
export function sharingKeyword(className: string, body: string): SharingKeyword | null {
  const code = apexCode(body);
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
  return testApexPattern(apexCode(body), SYSTEM_MODE);
}
