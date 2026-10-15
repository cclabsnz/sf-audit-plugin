// IST hidden must-never tests for INT-001 (MN-001..003). CI-only: the implementing agent never
// reads this folder. Run: node --experimental-vm-modules node_modules/jest/bin/jest.js --roots '<rootDir>/tests/hidden'
// Typecheck: pnpm -s exec tsc --noEmit -p tests/hidden/tsconfig.json
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { ApexSharingCheck } from '../../src/checks/impl/ApexSharingCheck.js';
import { ApexCrudFLSCheck } from '../../src/checks/impl/ApexCrudFLSCheck.js';
import { GuestExecutableApexCheck } from '../../src/checks/impl/GuestExecutableApexCheck.js';
import type { Finding } from '../../src/findings/Finding.js';

type Body = { name: string; body: string; symbolTable?: unknown };
type Result = { findings: Finding[] };

const ORG_INFO = {
  id: '00Dxx0000000000EAA', name: 'Acme', type: 'DE', isSandbox: false,
  instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com',
};
const PROFILE = '00exx0000000001AAA';

function bodiesCtx(apexBodies: Body[]): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query: (jest.fn() as any).mockImplementation(() => Promise.resolve([])), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: ORG_INFO,
    cache: { apexBodies } as any,
  } as any;
}

function guestCtx(guestClasses: string[], apexBodies: Body[]): AuditContext {
  const idOf = (n: string) => `01pxx${String(guestClasses.indexOf(n) + 1).padStart(10, '0')}AAA`;
  const queryAll = (jest.fn() as any).mockImplementation((q: string) => {
    if (/SetupEntityAccess/i.test(q)) return Promise.resolve(guestClasses.map((n) => ({ SetupEntityId: idOf(n), ParentId: PROFILE })));
    if (/FROM\s+User\b/i.test(q)) return Promise.resolve([{ Id: '005xx0000000001AAA', ProfileId: PROFILE, Username: 'guest@acme.example' }]);
    return Promise.resolve([]);
  });
  const names = guestClasses.map((n) => ({ Id: idOf(n), Name: n }));
  return {
    soql: { query: queryAll, queryAll } as any,
    tooling: { query: (jest.fn() as any).mockImplementation(() => Promise.resolve(names)), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: ORG_INFO,
    cache: { apexBodies } as any,
  } as any;
}

/** Any finding with this id (passed or not) that names the class in an affected-item label. */
const listsAny = (r: Result, id: string, cls: string) =>
  r.findings.some((f) => f.id === id && (f.affectedItems ?? []).some((i) => i.label.includes(cls)));
const active = (r: Result, id: string) => r.findings.find((f) => f.id === id && !f.passed);
const listsActive = (r: Result, id: string, cls: string) =>
  (active(r, id)?.affectedItems ?? []).some((i) => i.label.includes(cls));
const textOf = (f: Finding | undefined) =>
  f ? [f.title, f.detail, ...(f.affectedItems ?? []).flatMap((i) => [i.label, i.note ?? ''])].join('\n') : '';
const refs = (name: string, ...helpers: string[]) => ({
  name,
  externalReferences: helpers.map((h) => ({ name: h, namespace: null, references: [], methods: [], variables: [] })),
});

const sharing = new ApexSharingCheck();
const crud = new ApexCrudFLSCheck();
const guest = new GuestExecutableApexCheck();

// =============================================================================================
describe('MN-001 never report sharing bypass when sharing is enforced', () => {
  it('MN-001: lowercase "with system_mode" in a with-sharing @AuraEnabled class is not a portal sharing bypass', async () => {
    const body = 'public with sharing class LowerSys {\n  @AuraEnabled public static List<Account> go() { return [select Id from Account with system_mode]; }\n}';
    const r = await sharing.run(bodiesCtx([{ name: 'LowerSys', body }]));
    expect(listsAny(r, 'portal-exposed-apex-without-sharing', 'LowerSys')).toBe(false);
  });

  it('MN-001: "WITH   SYSTEM_MODE" split over lines in a with-sharing guest class is not CRITICAL unprotected', async () => {
    const body = 'public with sharing class SpacedSys {\n  public static List<Account> go() {\n    return [SELECT Id FROM Account\n      WITH\n        SYSTEM_MODE];\n  }\n}';
    const r = await guest.run(guestCtx(['SpacedSys'], [{ name: 'SpacedSys', body, symbolTable: refs('SpacedSys') }]));
    expect(listsAny(r, 'guest-executable-apex-unprotected', 'SpacedSys')).toBe(false);
  });

  it('MN-001: a with-sharing guest class whose comment and string mention "without sharing" is not unprotected', async () => {
    const body =
      '/* Previously declared without sharing; fixed in 2025. */\n' +
      'public with sharing class Fixed {\n' +
      "  private static final String NOTE = 'never run without sharing';\n" +
      '  // without sharing helper removed\n' +
      '  public static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}';
    const r = await guest.run(guestCtx(['Fixed'], [{ name: 'Fixed', body, symbolTable: refs('Fixed') }]));
    expect(listsAny(r, 'guest-executable-apex-unprotected', 'Fixed')).toBe(false);
    const rs = await sharing.run(bodiesCtx([{ name: 'Fixed', body: body.replace('public static', '@AuraEnabled public static') }]));
    expect(listsAny(rs, 'portal-exposed-apex-without-sharing', 'Fixed')).toBe(false);
  });

  it('MN-001: AccessLevel.SYSTEM_MODE inside Database.query in an inherited-sharing @AuraEnabled class is not a portal sharing bypass', async () => {
    const body = "public inherited sharing class InheritSys {\n  @AuraEnabled public static List<Account> go(String q) { return Database.query(q, AccessLevel.SYSTEM_MODE); }\n}";
    const r = await sharing.run(bodiesCtx([{ name: 'InheritSys', body }]));
    expect(listsAny(r, 'portal-exposed-apex-without-sharing', 'InheritSys')).toBe(false);
  });

  it('MN-001: a with-sharing guest class calling a no-keyword helper that uses SYSTEM_MODE is not unprotected', async () => {
    const r = await guest.run(guestCtx(['Facade'], [
      { name: 'Facade', body: 'public with sharing class Facade {\n  public static List<Account> go() { return SysHelper.fetch(); }\n}', symbolTable: refs('Facade', 'SysHelper') },
      { name: 'SysHelper', body: 'public class SysHelper {\n  public static List<Account> fetch() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}' },
    ]));
    expect(listsAny(r, 'guest-executable-apex-unprotected', 'Facade')).toBe(false);
  });

  it('MN-001: @RestResource with sharing and USER_MODE + SYSTEM_MODE is not a portal sharing bypass', async () => {
    const body =
      "@RestResource(urlMapping='/mix/*')\nglobal with sharing class MixRest {\n" +
      '  @HttpGet global static List<Account> a() { return [SELECT Id FROM Account WITH USER_MODE]; }\n' +
      '  @HttpPost global static void b(List<Account> rows) { Database.update(rows, AccessLevel.SYSTEM_MODE); }\n}';
    const r = await sharing.run(bodiesCtx([{ name: 'MixRest', body }]));
    expect(listsAny(r, 'portal-exposed-apex-without-sharing', 'MixRest')).toBe(false);
  });
});

// =============================================================================================
describe('MN-002 never report a guest-callable class as protected when it or a helper is without sharing', () => {
  it('MN-002: a without-sharing helper whose body also mentions "with sharing" in a comment still makes the caller unprotected', async () => {
    const r = await guest.run(guestCtx(['Portal'], [
      { name: 'Portal', body: 'public with sharing class Portal {\n  public static List<Account> go() { return Sneaky.fetch(); }\n}', symbolTable: refs('Portal', 'Sneaky') },
      {
        name: 'Sneaky',
        body: '// TODO: switch to with sharing once callers are reviewed\npublic without sharing class Sneaky {\n  /* with sharing would break the batch */\n  public static List<Account> fetch() { return [SELECT Id FROM Account]; }\n}',
      },
    ]));
    const f = active(r, 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'Portal')).toBe(true);
    expect(textOf(f)).toContain('Sneaky');
  });

  it('MN-002: a helper declared "WITHOUT   SHARING" (uppercase, extra spaces) makes the caller unprotected', async () => {
    const r = await guest.run(guestCtx(['Caller'], [
      { name: 'Caller', body: 'public with sharing class Caller {\n  public static void go() { LoudHelper.run(); }\n}', symbolTable: refs('Caller', 'LoudHelper') },
      { name: 'LoudHelper', body: 'PUBLIC WITHOUT   SHARING CLASS LoudHelper {\n  public static void run() { delete [SELECT Id FROM Contact]; }\n}' },
    ]));
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'Caller')).toBe(true);
  });

  it('MN-002: the without-sharing helper is found when it is not the first external reference', async () => {
    const r = await guest.run(guestCtx(['Multi'], [
      { name: 'Multi', body: 'public with sharing class Multi {\n  public static void go() { SafeOne.a(); SafeTwo.b(); Hidden.c(); }\n}', symbolTable: refs('Multi', 'SafeOne', 'SafeTwo', 'Hidden') },
      { name: 'SafeOne', body: 'public with sharing class SafeOne { public static void a() {} }' },
      { name: 'SafeTwo', body: 'public inherited sharing class SafeTwo { public static void b() {} }' },
      { name: 'Hidden', body: 'public without sharing class Hidden {\n  public static void c() { update [SELECT Id FROM Case]; }\n}' },
    ]));
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'Multi')).toBe(true);
    expect(textOf(active(r, 'guest-executable-apex-unprotected'))).toContain('Hidden');
  });

  it('MN-002: a SymbolTable reference spelled in a different case still resolves the without-sharing helper', async () => {
    const r = await guest.run(guestCtx(['CaseCaller'], [
      { name: 'CaseCaller', body: 'public with sharing class CaseCaller {\n  public static void go() { elevatedutil.run(); }\n}', symbolTable: refs('CaseCaller', 'elevatedutil') },
      { name: 'ElevatedUtil', body: 'public without sharing class ElevatedUtil {\n  public static void run() { delete [SELECT Id FROM Lead]; }\n}' },
    ]));
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'CaseCaller')).toBe(true);
  });

  it('MN-002: a with-sharing guest class using SYSTEM_MODE that also calls a without-sharing helper is CRITICAL unprotected, not merely HIGH', async () => {
    const r = await guest.run(guestCtx(['Both'], [
      { name: 'Both', body: 'public with sharing class Both {\n  public static List<Account> go() { Elev.x(); return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}', symbolTable: refs('Both', 'Elev') },
      { name: 'Elev', body: 'public without sharing class Elev { public static void x() { delete [SELECT Id FROM Opportunity]; } }' },
    ]));
    const f = active(r, 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'Both')).toBe(true);
  });

  it('MN-002: a guest class with no sharing keyword that uses SYSTEM_MODE is CRITICAL unprotected, not downgraded', async () => {
    const body = 'public class NoKeySys {\n  public static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}';
    const r = await guest.run(guestCtx(['NoKeySys'], [{ name: 'NoKeySys', body, symbolTable: refs('NoKeySys') }]));
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'NoKeySys')).toBe(true);
    expect(active(r, 'guest-executable-apex-unprotected')!.riskLevel).toBe('CRITICAL');
  });

  it('MN-002: a guest class declared "Without Sharing" in mixed case with a "with sharing" comment is CRITICAL unprotected', async () => {
    const body = '// should be with sharing\npublic Without Sharing class Mixed {\n  public static void go() { delete [SELECT Id FROM Account]; }\n}';
    const r = await guest.run(guestCtx(['Mixed'], [{ name: 'Mixed', body, symbolTable: refs('Mixed') }]));
    expect(listsActive(r, 'guest-executable-apex-unprotected', 'Mixed')).toBe(true);
  });

  it('MN-002: a no-sharing @RestResource class using WITH SYSTEM_MODE is still listed as portal-exposed without sharing', async () => {
    const body = "@RestResource(urlMapping='/nk/*')\nglobal class NoKeyRest {\n  @HttpGet global static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}";
    const r = await sharing.run(bodiesCtx([{ name: 'NoKeyRest', body }]));
    expect(listsActive(r, 'portal-exposed-apex-without-sharing', 'NoKeyRest')).toBe(true);
  });
});

// =============================================================================================
describe('MN-003 never let SYSTEM_MODE pass as CRUD/FLS enforcement', () => {
  it.each([
    ['lowercase with system_mode', 'Lc', 'public with sharing class Lc {\n  public List<Account> go() { return [select Id from Account with system_mode]; }\n}'],
    ['extra whitespace and newline', 'Ws', 'public with sharing class Ws {\n  public List<Account> go() { return [SELECT Id FROM Account WITH \t\n   SYSTEM_MODE]; }\n}'],
    ['AccessLevel.SYSTEM_MODE in Database.query', 'Dq', "public with sharing class Dq {\n  public List<Account> go(String q) { return Database.query(q, AccessLevel.SYSTEM_MODE); }\n}"],
    ['lowercase accesslevel.system_mode in queryWithBinds', 'Qb', "public with sharing class Qb {\n  public List<Account> go(Map<String,Object> b) { return Database.queryWithBinds('SELECT Id FROM Account WHERE Name = :n', b, accesslevel.system_mode); }\n}"],
    ['AccessLevel.SYSTEM_MODE as the third DML argument', 'Dml3', 'public with sharing class Dml3 {\n  public void go(List<Account> rows) { Database.update(rows, false, AccessLevel.SYSTEM_MODE); }\n}'],
    ['AccessLevel.SYSTEM_MODE in getQueryLocator', 'Loc', "public with sharing class Loc implements Database.Batchable<SObject> {\n  public Database.QueryLocator start(Database.BatchableContext c) { return Database.getQueryLocator('SELECT Id FROM Contact', AccessLevel.SYSTEM_MODE); }\n  public void execute(Database.BatchableContext c, List<SObject> s) {}\n  public void finish(Database.BatchableContext c) {}\n}"],
  ])('MN-003: %s is listed in apex-crud-fls-system-mode and never in apex-crud-fls-ok', async (_l, name, body) => {
    const r = await crud.run(bodiesCtx([{ name, body }]));
    expect(listsActive(r, 'apex-crud-fls-system-mode', name)).toBe(true);
    expect(listsAny(r, 'apex-crud-fls-ok', name)).toBe(false);
  });

  it('MN-003: USER_MODE plus SYSTEM_MODE in the same class still lists it as SYSTEM_MODE', async () => {
    const body =
      'public with sharing class UserThenSys {\n' +
      '  public List<Account> a() { return [SELECT Id FROM Account WITH USER_MODE]; }\n' +
      '  public void b(List<Account> r) { Database.insert(r, AccessLevel.USER_MODE); }\n' +
      '  public List<Contact> c() { return [SELECT Id, Email FROM Contact WITH SYSTEM_MODE]; }\n}';
    const r = await crud.run(bodiesCtx([{ name: 'UserThenSys', body }]));
    expect(listsActive(r, 'apex-crud-fls-system-mode', 'UserThenSys')).toBe(true);
    expect(listsAny(r, 'apex-crud-fls-ok', 'UserThenSys')).toBe(false);
  });

  it('MN-003: stripInaccessible and isAccessible checks alongside SYSTEM_MODE do not excuse it', async () => {
    const body =
      'public with sharing class Belt {\n' +
      '  public List<Account> go() {\n' +
      '    if (Schema.sObjectType.Account.isAccessible() && Schema.sObjectType.Account.fields.Name.isAccessible()) {\n' +
      '      return (List<Account>) Security.stripInaccessible(AccessType.READABLE, [SELECT Id FROM Account WITH SECURITY_ENFORCED]).getRecords();\n' +
      '    }\n' +
      "    return Database.query('SELECT Id, Name FROM Account', AccessLevel.SYSTEM_MODE);\n" +
      '  }\n}';
    const r = await crud.run(bodiesCtx([{ name: 'Belt', body }]));
    expect(listsActive(r, 'apex-crud-fls-system-mode', 'Belt')).toBe(true);
    expect(textOf(active(r, 'apex-crud-fls-system-mode'))).toMatch(/SYSTEM_MODE/);
  });

  it('MN-003: a with-sharing guest class using lowercase system_mode lands in the HIGH guest system-mode finding', async () => {
    const body = 'public with sharing class GuestLc {\n  public static List<Account> go() { return [select Id from Account with system_mode]; }\n}';
    const r = await guest.run(guestCtx(['GuestLc'], [{ name: 'GuestLc', body, symbolTable: refs('GuestLc') }]));
    expect(listsActive(r, 'guest-executable-apex-system-mode', 'GuestLc')).toBe(true);
    expect(active(r, 'guest-executable-apex-system-mode')!.riskLevel).toBe('HIGH');
    expect(r.findings.some((f) => f.id === 'guest-executable-apex-ok' && f.passed)).toBe(false);
  });
});
