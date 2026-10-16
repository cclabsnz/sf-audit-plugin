// IST visible rule tests for spec/apex-access-mode.md (RULE-001..006, INT-001).
// Written from the intent and rules only; each test names the rule it proves.
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { ApexSharingCheck } from '../../../src/checks/impl/ApexSharingCheck.js';
import { ApexCrudFLSCheck } from '../../../src/checks/impl/ApexCrudFLSCheck.js';
import { GuestExecutableApexCheck } from '../../../src/checks/impl/GuestExecutableApexCheck.js';
import { capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { Capability } from '../../../src/chains/Capability.js';

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

// ---------------------------------------------------------------------------------------------
describe('RULE-001 SYSTEM_MODE under with sharing is a CRUD/FLS bypass, not a sharing bypass', () => {
  const aura = (name: string, op: string) =>
    `public with sharing class ${name} {\n  @AuraEnabled\n  public static List<Account> go(String q) {\n    ${op}\n  }\n}`;

  it.each([
    ['WITH SYSTEM_MODE', 'AuraSysA', aura('AuraSysA', "return [SELECT Id, Name FROM Account WITH SYSTEM_MODE];")],
    ['AccessLevel.SYSTEM_MODE', 'AuraSysB', aura('AuraSysB', "return Database.query('SELECT Id FROM Account', AccessLevel.SYSTEM_MODE);")],
    ['@RemoteAction + WITH SYSTEM_MODE', 'RemoteSys',
      'global with sharing class RemoteSys {\n  @RemoteAction\n  global static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}'],
    ['@RestResource + WITH SYSTEM_MODE', 'RestSys',
      "@RestResource(urlMapping='/sys/*')\nglobal with sharing class RestSys {\n  @HttpGet\n  global static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}"],
  ])('RULE-001: %s in a with-sharing exposed class is not listed by portal-exposed-apex-without-sharing', async (_l, name, body) => {
    const r = await sharing.run(bodiesCtx([{ name, body }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', name)).toBe(false);
  });

  it.each([
    ['WITH SYSTEM_MODE', 'AuraSysA', aura('AuraSysA', "return [SELECT Id, Name FROM Account WITH SYSTEM_MODE];")],
    ['AccessLevel.SYSTEM_MODE', 'AuraSysB', aura('AuraSysB', "return Database.query('SELECT Id FROM Account', AccessLevel.SYSTEM_MODE);")],
  ])('RULE-001: %s in a with-sharing @AuraEnabled class is listed in apex-crud-fls-system-mode, naming SYSTEM_MODE', async (_l, name, body) => {
    const r = await crud.run(bodiesCtx([{ name, body }]));
    const f = byId(r, 'apex-crud-fls-system-mode');
    expect(f).toBeDefined();
    expect(labels(f).some((l) => l.includes(name))).toBe(true);
    expect(textOf(f)).toMatch(/SYSTEM_MODE/);
  });

  it('RULE-001 (negative): a with-sharing @AuraEnabled class without SYSTEM_MODE is in neither finding', async () => {
    const body = aura('AuraUser', 'return [SELECT Id FROM Account WITH USER_MODE];');
    const rs = await sharing.run(bodiesCtx([{ name: 'AuraUser', body }]));
    const rc = await crud.run(bodiesCtx([{ name: 'AuraUser', body }]));
    expect(lists(rs, 'portal-exposed-apex-without-sharing', 'AuraUser')).toBe(false);
    expect(lists(rc, 'apex-crud-fls-system-mode', 'AuraUser')).toBe(false);
  });

  it('RULE-001 (negative): a without-sharing @AuraEnabled class using SYSTEM_MODE is still a sharing bypass', async () => {
    const body = 'public without sharing class AuraNoShare {\n  @AuraEnabled\n  public static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}';
    const r = await sharing.run(bodiesCtx([{ name: 'AuraNoShare', body }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', 'AuraNoShare')).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RULE-002 SYSTEM_MODE never counts as CRUD/FLS enforcement', () => {
  it('RULE-002: a class with SOQL WITH SYSTEM_MODE is listed in apex-crud-fls-system-mode', async () => {
    const body = 'public with sharing class SysSoql {\n  public List<Contact> go() { return [SELECT Id, Email FROM Contact WITH SYSTEM_MODE]; }\n}';
    const r = await crud.run(bodiesCtx([{ name: 'SysSoql', body }]));
    expect(lists(r, 'apex-crud-fls-system-mode', 'SysSoql')).toBe(true);
  });

  it('RULE-002: a class with DML via AccessLevel.SYSTEM_MODE is listed in apex-crud-fls-system-mode', async () => {
    const body = 'public with sharing class SysDml {\n  public void go(List<Account> rows) { Database.insert(rows, AccessLevel.SYSTEM_MODE); }\n}';
    const r = await crud.run(bodiesCtx([{ name: 'SysDml', body }]));
    expect(lists(r, 'apex-crud-fls-system-mode', 'SysDml')).toBe(true);
  });

  it('RULE-002: SYSTEM_MODE is listed even when the class also contains a CRUD/FLS check', async () => {
    const body =
      'public with sharing class SysWithCheck {\n' +
      '  public List<Account> go() {\n' +
      '    if (!Schema.sObjectType.Account.isAccessible()) { return null; }\n' +
      '    List<Account> a = [SELECT Id FROM Account WITH SECURITY_ENFORCED];\n' +
      '    a = (List<Account>) Security.stripInaccessible(AccessType.READABLE, a).getRecords();\n' +
      '    return [SELECT Id, Name FROM Account WITH SYSTEM_MODE];\n' +
      '  }\n}';
    const r = await crud.run(bodiesCtx([{ name: 'SysWithCheck', body }]));
    expect(lists(r, 'apex-crud-fls-system-mode', 'SysWithCheck')).toBe(true);
    expect(lists(r, 'apex-crud-fls-ok', 'SysWithCheck')).toBe(false);
  });

  it('RULE-002: SYSTEM_MODE is listed even when the class also uses USER_MODE elsewhere', async () => {
    const body =
      'public with sharing class SysAndUser {\n' +
      '  public List<Account> a() { return [SELECT Id FROM Account WITH USER_MODE]; }\n' +
      "  public List<Account> b() { return Database.query('SELECT Id FROM Account', AccessLevel.SYSTEM_MODE); }\n}";
    const r = await crud.run(bodiesCtx([{ name: 'SysAndUser', body }]));
    expect(lists(r, 'apex-crud-fls-system-mode', 'SysAndUser')).toBe(true);
  });

  it.each([
    ['WITH USER_MODE', 'UserSoql', 'public with sharing class UserSoql {\n  public List<Account> go() { return [SELECT Id FROM Account WITH USER_MODE]; }\n}'],
    ['AccessLevel.USER_MODE', 'UserDml', 'public with sharing class UserDml {\n  public void go(List<Account> rows) { Database.insert(rows, AccessLevel.USER_MODE); }\n}'],
  ])('RULE-002 (negative): %s alone counts as enforcement', async (_l, name, body) => {
    const r = await crud.run(bodiesCtx([{ name, body }]));
    expect(lists(r, 'apex-crud-fls-system-mode', name)).toBe(false);
    expect(lists(r, 'apex-crud-fls-missing', name)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RULE-003 Guest-callable SYSTEM_MODE under with sharing is HIGH, not CRITICAL', () => {
  it('RULE-003: a with-sharing guest class using WITH SYSTEM_MODE is in a HIGH guest-executable-apex-system-mode finding', async () => {
    const body = 'public with sharing class GuestSys {\n  @AuraEnabled public static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}';
    const r = await guest.run(guestCtx(['GuestSys'], [{ name: 'GuestSys', body }]));
    const f = byId(r, 'guest-executable-apex-system-mode');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(labels(f).some((l) => l.includes('GuestSys'))).toBe(true);
  });

  it('RULE-003: a with-sharing guest class using AccessLevel.SYSTEM_MODE is not in the CRITICAL unprotected finding', async () => {
    const body = "public with sharing class GuestSysB {\n  public static List<Account> go() { return Database.query('SELECT Id FROM Account', AccessLevel.SYSTEM_MODE); }\n}";
    const r = await guest.run(guestCtx(['GuestSysB'], [{ name: 'GuestSysB', body }]));
    expect(lists(r, 'guest-executable-apex-system-mode', 'GuestSysB')).toBe(true);
    expect(byId(r, 'guest-executable-apex-system-mode')!.riskLevel).toBe('HIGH');
    expect(lists(r, 'guest-executable-apex-unprotected', 'GuestSysB')).toBe(false);
  });

  it('RULE-003 (negative): a with-sharing guest class without SYSTEM_MODE is in neither finding', async () => {
    const body = 'public with sharing class GuestPlain {\n  public static List<Account> go() { return [SELECT Id FROM Account WITH USER_MODE]; }\n}';
    const r = await guest.run(guestCtx(['GuestPlain'], [{ name: 'GuestPlain', body }]));
    expect(lists(r, 'guest-executable-apex-system-mode', 'GuestPlain')).toBe(false);
    expect(lists(r, 'guest-executable-apex-unprotected', 'GuestPlain')).toBe(false);
  });

  it('RULE-003 (negative): a without-sharing guest class using SYSTEM_MODE stays CRITICAL unprotected', async () => {
    const body = 'public without sharing class GuestOpen {\n  public static List<Account> go() { return [SELECT Id FROM Account WITH SYSTEM_MODE]; }\n}';
    const r = await guest.run(guestCtx(['GuestOpen'], [{ name: 'GuestOpen', body }]));
    const f = byId(r, 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(labels(f).some((l) => l.includes('GuestOpen'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RULE-004 A guest-callable class calling a without-sharing helper is unprotected', () => {
  const caller = (name: string, helper: string): Body => ({
    name,
    body: `public with sharing class ${name} {\n  @AuraEnabled public static List<Account> go() { return ${helper}.fetch(); }\n}`,
    symbolTable: { name, externalReferences: [{ name: helper, namespace: null, references: [], methods: [], variables: [] }] },
  });

  it('RULE-004: a with-sharing guest class referencing a without-sharing helper is CRITICAL unprotected, naming the helper', async () => {
    const r = await guest.run(guestCtx(['GuestFacade'], [
      caller('GuestFacade', 'ElevatedHelper'),
      { name: 'ElevatedHelper', body: 'public without sharing class ElevatedHelper {\n  public static List<Account> fetch() { return [SELECT Id FROM Account]; }\n}' },
    ]));
    const f = byId(r, 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(labels(f).some((l) => l.includes('GuestFacade'))).toBe(true);
    expect(textOf(f)).toContain('ElevatedHelper');
  });

  it('RULE-004 (negative): a helper with no sharing keyword (runs with the caller\'s) does not make it unprotected', async () => {
    const r = await guest.run(guestCtx(['GuestFacade'], [
      caller('GuestFacade', 'PlainHelper'),
      { name: 'PlainHelper', body: 'public class PlainHelper {\n  public static List<Account> fetch() { return [SELECT Id FROM Account]; }\n}' },
    ]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'GuestFacade')).toBe(false);
  });

  it('RULE-004 (negative): a helper that only uses dynamic SOQL does not make it unprotected', async () => {
    const r = await guest.run(guestCtx(['GuestFacade'], [
      caller('GuestFacade', 'DynamicHelper'),
      { name: 'DynamicHelper', body: "public class DynamicHelper {\n  public static List<Account> fetch() { return Database.query('SELECT Id FROM Account'); }\n}" },
    ]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'GuestFacade')).toBe(false);
  });

  it('RULE-004 (negative): a with-sharing guest class with no references and no SYSTEM_MODE is not unprotected', async () => {
    const r = await guest.run(guestCtx(['Lonely'], [{
      name: 'Lonely',
      body: 'public with sharing class Lonely {\n  public static List<Account> go() { return [SELECT Id FROM Account]; }\n}',
      symbolTable: { name: 'Lonely', externalReferences: [] },
    }]));
    expect(lists(r, 'guest-executable-apex-unprotected', 'Lonely')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RULE-005 @RestResource classes are externally exposed', () => {
  const rest = (name: string, decl: string) =>
    `@RestResource(urlMapping='/${name}/*')\nglobal ${decl}class ${name} {\n  @HttpGet\n  global static List<Account> go() { return [SELECT Id FROM Account]; }\n}`;

  it('RULE-005: a without-sharing @RestResource class is listed by portal-exposed-apex-without-sharing', async () => {
    const r = await sharing.run(bodiesCtx([{ name: 'RestOpen', body: rest('RestOpen', 'without sharing ') }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', 'RestOpen')).toBe(true);
  });

  it('RULE-005: a @RestResource class with no sharing declaration is listed by portal-exposed-apex-without-sharing', async () => {
    const r = await sharing.run(bodiesCtx([{ name: 'RestSilent', body: rest('RestSilent', '') }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', 'RestSilent')).toBe(true);
  });

  it('RULE-005: listed as @AuraEnabled and @RemoteAction classes are, side by side', async () => {
    const r = await sharing.run(bodiesCtx([
      { name: 'RestOpen', body: rest('RestOpen', 'without sharing ') },
      { name: 'AuraOpen', body: 'public without sharing class AuraOpen {\n  @AuraEnabled public static void go() {}\n}' },
      { name: 'RemoteOpen', body: 'global without sharing class RemoteOpen {\n  @RemoteAction global static void go() {}\n}' },
    ]));
    for (const n of ['RestOpen', 'AuraOpen', 'RemoteOpen']) {
      expect(lists(r, 'portal-exposed-apex-without-sharing', n)).toBe(true);
    }
  });

  it.each([
    ['with sharing', 'RestShared', 'with sharing '],
    ['inherited sharing', 'RestInherited', 'inherited sharing '],
  ])('RULE-005 (negative): a %s @RestResource class is not listed', async (_l, name, decl) => {
    const r = await sharing.run(bodiesCtx([{ name, body: rest(name, decl) }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', name)).toBe(false);
  });

  it('RULE-005 (negative): a without-sharing class with no exposure annotation is not listed', async () => {
    const r = await sharing.run(bodiesCtx([{ name: 'Internal', body: 'public without sharing class Internal {\n  public void go() {}\n}' }]));
    expect(lists(r, 'portal-exposed-apex-without-sharing', 'Internal')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RULE-006 The new findings are wired into attack-chain correlation', () => {
  const f = (id: string): Finding => ({ id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '' });
  const present = (fs: Finding[]) => {
    const s = new Set<Capability>();
    for (const x of fs) for (const c of capabilitiesFor(x).grants) s.add(c);
    return s;
  };
  const chain = () => NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;

  it('RULE-006: guest-executable-apex-system-mode grants code-exec and data-read', () => {
    const grants = capabilitiesFor(f('guest-executable-apex-system-mode')).grants;
    expect(grants).toEqual(expect.arrayContaining(['code-exec', 'data-read']));
  });

  it('RULE-006 (negative): guest-executable-apex-system-mode does not grant data-read-bulk', () => {
    const grants = capabilitiesFor(f('guest-executable-apex-system-mode')).grants;
    expect(grants).toContain('code-exec');
    expect(grants).not.toContain('data-read-bulk');
  });

  it('RULE-006: guest-executable-apex-system-mode is a step in unauth-bulk-exfil, like guest-executable-apex-exposed', () => {
    for (const id of ['guest-executable-apex-system-mode', 'guest-executable-apex-exposed']) {
      const fs = [f('guest-user-baseline'), f('guest-user-read-access'), f(id)];
      const steps = chain().match(present(fs), fs);
      expect(steps).not.toBeNull();
      expect(steps!.map((s) => s.id)).toContain(id);
    }
  });

  it('RULE-006 (negative): without a guest foothold, guest-executable-apex-system-mode alone does not form unauth-bulk-exfil', () => {
    const fs = [f('guest-executable-apex-system-mode')];
    expect(chain().match(present(fs), fs)).toBeNull();
  });

  it('RULE-006: apex-crud-fls-system-mode grants data-read, like apex-crud-fls-missing', () => {
    const sys = capabilitiesFor(f('apex-crud-fls-system-mode')).grants;
    const missing = capabilitiesFor(f('apex-crud-fls-missing')).grants;
    expect(sys).toContain('data-read');
    expect([...sys].sort()).toEqual([...missing].sort());
  });

  it('RULE-006 (negative): apex-crud-fls-system-mode does not grant data-read-bulk or data-write', () => {
    const sys = capabilitiesFor(f('apex-crud-fls-system-mode')).grants;
    expect(sys).toContain('data-read');
    expect(sys).not.toContain('data-read-bulk');
    expect(sys).not.toContain('data-write');
  });
});
