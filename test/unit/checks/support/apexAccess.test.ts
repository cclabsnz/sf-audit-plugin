import { enteredOnlyThroughAura, omittedSharingEnforced, sharingKeyword, usesSystemMode } from '../../../../src/checks/support/apexAccess.js';

describe('sharingKeyword', () => {
  it('reads the keyword on the named class declaration', () => {
    expect(sharingKeyword('A', 'public with sharing class A {}')).toBe('with');
    expect(sharingKeyword('A', 'global without sharing class A {}')).toBe('without');
    expect(sharingKeyword('A', 'public inherited sharing class A {}')).toBe('inherited');
    expect(sharingKeyword('A', 'public class A {}')).toBe('none');
  });

  it('accepts modifiers on either side of the keyword, in any case', () => {
    expect(sharingKeyword('A', 'public virtual WITHOUT   SHARING class A {}')).toBe('without');
    expect(sharingKeyword('A', 'global with sharing virtual class A {}')).toBe('with');
  });

  it('ignores sharing words in comments', () => {
    expect(sharingKeyword('A', '// always use with sharing\npublic without sharing class A {}')).toBe('without');
    expect(sharingKeyword('A', '/* with sharing */ public class A {}')).toBe('none');
  });

  it('reads the outer class, not an inner one with another keyword', () => {
    const body = 'public without sharing class Outer {\n  public with sharing class Inner {}\n}';
    expect(sharingKeyword('Outer', body)).toBe('without');
    expect(sharingKeyword('Inner', body)).toBe('with');
  });

  it('returns null when no class of that name is declared', () => {
    expect(sharingKeyword('A', 'public interface A {}')).toBeNull();
    expect(sharingKeyword('A', 'public with sharing class AB {}')).toBeNull();
  });
});

describe('usesSystemMode', () => {
  it('finds SYSTEM_MODE in SOQL, DML access levels and dynamic SOQL strings', () => {
    expect(usesSystemMode('[SELECT Id FROM Account WITH SYSTEM_MODE]')).toBe(true);
    expect(usesSystemMode('Database.insert(rows, AccessLevel.SYSTEM_MODE);')).toBe(true);
    expect(usesSystemMode('Database.query(q, AccessLevel . system_mode);')).toBe(true);
    expect(usesSystemMode("Database.query('SELECT Id FROM Account with  system_mode');")).toBe(true);
  });

  it('ignores SYSTEM_MODE in comments, and does not confuse USER_MODE', () => {
    expect(usesSystemMode('// never use WITH SYSTEM_MODE here\n[SELECT Id FROM Account WITH USER_MODE]')).toBe(false);
    expect(usesSystemMode('/* AccessLevel.SYSTEM_MODE */')).toBe(false);
  });
});

describe('omittedSharingEnforced (RULE-007)', () => {
  const bodies: Record<string, string> = {
    Child: 'public class Child extends Mid { }',
    Mid: 'public virtual class Mid extends Root { }',
    Root: 'public virtual class Root { }',
    Declared: 'public virtual with sharing class Declared { }',
    OnDeclared: 'public class OnDeclared extends Declared { }',
  };
  const lookup = (n: string) => bodies[n];
  const at = (v: Record<string, number>) => (n: string) => v[n];

  it('is true at 67.0 with no parent', () => {
    expect(omittedSharingEnforced('Root', bodies.Root, lookup, at({ Root: 67 }))).toBe(true);
    expect(omittedSharingEnforced('Root', bodies.Root, lookup, at({ Root: 66 }))).toBe(false);
  });

  it('needs every keyword-less class up the chain at 67.0', () => {
    expect(omittedSharingEnforced('Child', bodies.Child, lookup, at({ Child: 67, Mid: 67, Root: 67 }))).toBe(true);
    expect(omittedSharingEnforced('Child', bodies.Child, lookup, at({ Child: 67, Mid: 67, Root: 50 }))).toBe(false);
  });

  it('stops at a parent that declares a keyword', () => {
    expect(omittedSharingEnforced('OnDeclared', bodies.OnDeclared, lookup, at({ OnDeclared: 67, Declared: 40 }))).toBe(true);
  });

  it('is false for an unknown version or an unknown parent', () => {
    expect(omittedSharingEnforced('Root', bodies.Root, lookup, at({}))).toBe(false);
    expect(omittedSharingEnforced('X', 'public class X extends Pkg { }', () => undefined, at({ X: 67 }))).toBe(false);
  });

describe('omittedSharingEnforced with a declaring parent', () => {
  it('is false when the chain reaches a without sharing parent, true for with or inherited', () => {
    const at = () => 67;
    for (const [kw, expected] of [['without', false], ['with', true], ['inherited', true]] as const) {
      const bodies: Record<string, string> = { C: 'public class C extends P { }', P: `public virtual ${kw} sharing class P { }` };
      expect({ kw, r: omittedSharingEnforced('C', bodies.C, (n) => bodies[n], at) }).toEqual({ kw, r: expected });
    }
  });
});

describe('enteredOnlyThroughAura (RULE-008)', () => {
  it.each([
    ['@AuraEnabled only', 'public class A { @AuraEnabled public static void a() {} }', true],
    ['no @AuraEnabled', 'public class A { public static void a() {} }', false],
    ['@RemoteAction too', 'public class A { @AuraEnabled public static void a() {} @RemoteAction public static void b() {} }', false],
    ['@RestResource', "@RestResource(urlMapping='/a') public class A { @AuraEnabled public static void a() {} }", false],
    ['webservice', 'global class A { @AuraEnabled public static void a() {} webservice static void b() {} }', false],
    ['Visualforce controller', 'public class A { @AuraEnabled public static void a() {} public A(ApexPages.StandardController c) {} }', false],
    ['flow action', 'public class A { @AuraEnabled public static void a() {} @InvocableMethod public static void b() {} }', false],
    ['page properties', 'public class A { @AuraEnabled public static void a() {} public String name { get; set; } }', false],
    ['@AuraEnabled only in a comment', 'public class A { // @AuraEnabled\n public static void a() {} }', false],
  ])('%s', (_label, body, expected) => expect(enteredOnlyThroughAura(body)).toBe(expected));
});
});
