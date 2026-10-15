import { sharingKeyword, usesSystemMode } from '../../../../src/checks/support/apexAccess.js';

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
