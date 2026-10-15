// Regression tests for gaps found by the IST verifier, on top of RULE-001..006. Each names its rule.
// Harness copied from apexAccessMode.rules.test.ts.
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { ApexSharingCheck } from '../../../src/checks/impl/ApexSharingCheck.js';
import { ApexCrudFLSCheck } from '../../../src/checks/impl/ApexCrudFLSCheck.js';
import { GuestExecutableApexCheck } from '../../../src/checks/impl/GuestExecutableApexCheck.js';
import type { Finding } from '../../../src/findings/Finding.js';

type Body = { name: string; body: string; symbolTable?: unknown };
type Result = { findings: Finding[] };

const INSTANCE = 'https://acme.my.salesforce.com';
const ORG_INFO = { id: '00Dxx0000000000EAA', name: 'Acme', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: INSTANCE };

/** Context for the body-only checks (apex-sharing, apex-crud-fls). */
function bodiesCtx(apexBodies: Body[]): AuditContext {
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() => Promise.resolve([])),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: ORG_INFO,
    cache: { apexBodies } as any,
  } as any;
}

const PROFILE = '00exx0000000001AAA';

/**
 * Context for guest-executable-apex: one active guest user whose profile can execute exactly the
 * classes named in `guestClasses`. Queries are answered by content, not call order.
 */
function guestCtx(guestClasses: string[], apexBodies: Body[]): AuditContext {
  const idOf = (n: string) => `01pxx${String(guestClasses.indexOf(n) + 1).padStart(10, '0')}AAA`;
  const queryAll = (jest.fn() as any).mockImplementation((q: string) => {
    if (/SetupEntityAccess/i.test(q)) {
      return Promise.resolve(guestClasses.map((n) => ({ SetupEntityId: idOf(n), ParentId: PROFILE })));
    }
    if (/FROM\s+User\b/i.test(q)) {
      return Promise.resolve([{ Id: '005xx0000000001AAA', ProfileId: PROFILE, Username: 'guest@acme.example' }]);
    }
    return Promise.resolve([]);
  });
  const names = guestClasses.map((n) => ({ Id: idOf(n), Name: n }));
  return {
    soql: { query: queryAll, queryAll } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() => Promise.resolve(names)),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: ORG_INFO,
    cache: { apexBodies } as any,
  } as any;
}

const byId = (r: Result, id: string) => r.findings.find((f) => f.id === id && !f.passed);
const labels = (f: Finding | undefined) => (f?.affectedItems ?? []).map((i) => i.label);
const lists = (r: Result, id: string, cls: string) => labels(byId(r, id)).some((l) => l.includes(cls));
const textOf = (f: Finding | undefined) =>
  f ? [f.title, f.detail, ...(f.affectedItems ?? []).flatMap((i) => [i.label, i.note ?? ''])].join('\n') : '';

const sharing = new ApexSharingCheck();
const crud = new ApexCrudFLSCheck();
const guest = new GuestExecutableApexCheck();


const ref = (name: string, namespace: string | null = null) => ({ name, namespace, references: [], methods: [], variables: [] });

describe('verifier regressions', () => {
  it('RULE-005: a without-sharing REST class whose urlMapping contains /* is still listed', async () => {
    // The '/*' in the mapping must not open a comment that runs to the method's doc comment and
    // swallows the class declaration between them.
    const body = "@RestResource(urlMapping='/orders/*')\nglobal without sharing class OrdersApi {\n  /** Lists orders. */\n  @HttpGet global static List<Account> get() { return [SELECT Id FROM Account]; }\n}";
    const r = await sharing.run(bodiesCtx([{ name: 'OrdersApi', body }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', 'OrdersApi')).toBe(true);
    const g = await guest.run(guestCtx(['OrdersApi'], [{ name: 'OrdersApi', body }]));
    expect(lists(g, 'guest-executable-apex-unprotected', 'OrdersApi')).toBe(true);
  });

  it('RULE-004: a with-sharing guest class whose inner class is without sharing is unprotected', async () => {
    const body = 'public with sharing class Outer {\n  public without sharing class Worker { List<Account> go() { return [SELECT Id FROM Account]; } }\n}';
    const r = await guest.run(guestCtx(['Outer'], [{ name: 'Outer', body }]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'Outer')).toBe(true);
  });

  it('RULE-004: a without-sharing class two calls away still makes the guest class unprotected', async () => {
    const r = await guest.run(guestCtx(['Facade'], [
      { name: 'Facade', body: 'public with sharing class Facade { }', symbolTable: { externalReferences: [ref('Middle')] } },
      { name: 'Middle', body: 'public class Middle { }', symbolTable: { externalReferences: [ref('Deep')] } },
      { name: 'Deep', body: 'public without sharing class Deep { }' },
    ]));
    expect(textOf(byId(r, 'guest-executable-apex-unprotected'))).toContain('Deep');
  });

  it('RULE-004: a helper is found whatever case the SymbolTable spells it in', async () => {
    const r = await guest.run(guestCtx(['Facade'], [
      { name: 'Facade', body: 'public with sharing class Facade { }', symbolTable: { externalReferences: [ref('ELEVATEDhelper')] } },
      { name: 'ElevatedHelper', body: 'public without sharing class ElevatedHelper { }' },
    ]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'Facade')).toBe(true);
  });

  it('RULE-004: a namespaced reference does not resolve to a local class of the same name', async () => {
    const r = await guest.run(guestCtx(['Facade'], [
      { name: 'Facade', body: 'public with sharing class Facade { }', symbolTable: { externalReferences: [ref('Helper', 'vendorns')] } },
      { name: 'Helper', body: 'public without sharing class Helper { }' },
    ]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'Facade')).toBe(false);
  });

  it('RULE-003: SYSTEM_MODE in a with-sharing helper puts the guest class in the HIGH finding, naming the helper', async () => {
    const r = await guest.run(guestCtx(['Facade'], [
      { name: 'Facade', body: 'public with sharing class Facade { }', symbolTable: { externalReferences: [ref('Reader')] } },
      { name: 'Reader', body: 'public with sharing class Reader { List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; } }' },
    ]));
    const f = byId(r, 'guest-executable-apex-system-mode');
    expect(f?.riskLevel).toBe('HIGH');
    expect(textOf(f)).toContain('Reader');
  });

  it('RULE-002: getQueryLocator with AccessLevel.SYSTEM_MODE is listed', async () => {
    const body = "public with sharing class Locator { Object go() { return Database.getQueryLocator('SELECT Id FROM Account', AccessLevel.SYSTEM_MODE); } }";
    expect(lists(await crud.run(bodiesCtx([{ name: 'Locator', body }])), 'apex-crud-fls-system-mode', 'Locator')).toBe(true);
  });

  it('RULE-002: a batch class using SYSTEM_MODE is not exempt', async () => {
    const body = 'public with sharing class Nightly implements Database.Batchable<SObject> { void run() { List<Account> a = [SELECT Id FROM Account WITH SYSTEM_MODE]; } }';
    expect(lists(await crud.run(bodiesCtx([{ name: 'Nightly', body }])), 'apex-crud-fls-system-mode', 'Nightly')).toBe(true);
  });

  it('RULE-002: `insert as system` is SYSTEM_MODE, even beside a CRUD check', async () => {
    const body = 'public with sharing class Writer { void go(Account a) { if (Schema.sObjectType.Account.isCreateable()) {} insert as system a; } }';
    expect(lists(await crud.run(bodiesCtx([{ name: 'Writer', body }])), 'apex-crud-fls-system-mode', 'Writer')).toBe(true);
  });

  it('RULE-002: `as user` DML counts as enforcement', async () => {
    const body = 'public with sharing class Writer { void go(Account a) { insert as user a; } }';
    const r = await crud.run(bodiesCtx([{ name: 'Writer', body }]));
    expect(lists(r, 'apex-crud-fls-missing', 'Writer') || lists(r, 'apex-crud-fls-system-mode', 'Writer')).toBe(false);
  });

  it('RULE-002: USER_MODE in a comment enforces nothing, and SYSTEM_MODE in a comment bypasses nothing', async () => {
    const commentOnlyUser = 'public with sharing class A { // TODO add WITH USER_MODE\n List<Account> go() { return [SELECT Id FROM Account]; } }';
    const commentOnlySystem = 'public with sharing class B { /* was WITH SYSTEM_MODE */ List<Account> go() { return [SELECT Id FROM Account WITH USER_MODE]; } }';
    const r = await crud.run(bodiesCtx([{ name: 'A', body: commentOnlyUser }, { name: 'B', body: commentOnlySystem }]));
    expect(lists(r, 'apex-crud-fls-missing', 'A')).toBe(true);
    expect(lists(r, 'apex-crud-fls-system-mode', 'B')).toBe(false);
  });
});
