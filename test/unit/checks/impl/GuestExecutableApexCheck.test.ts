import { jest } from '@jest/globals';
import { GuestExecutableApexCheck } from '../../../../src/checks/impl/GuestExecutableApexCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Mocks { guestUsers: unknown[]; setupAccess: unknown[]; apexNames: unknown[]; }

function makeCtx(m: Mocks, apexBodies?: Array<{ name: string; body: string }>): AuditContext {
  const soqlQueryAll = jest.fn() as any;
  soqlQueryAll
    .mockResolvedValueOnce(m.guestUsers)   // guest users
    .mockResolvedValueOnce([{ PermissionSetId: '0PSP0000000AbCdEAA' }]) // their permission sets
    .mockResolvedValueOnce(m.setupAccess); // SetupEntityAccess
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockResolvedValue(m.apexNames); // ApexClass id→name
  return {
    soql: { query: jest.fn(), queryAll: soqlQueryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: apexBodies ? { apexBodies } : {},
  } as any;
}

describe('GuestExecutableApexCheck', () => {
  const check = new GuestExecutableApexCheck();

  it('passes when there are no guest users', async () => {
    const ctx = makeCtx({ guestUsers: [], setupAccess: [], apexNames: [] });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-none' && f.passed)).toBe(true);
  });

  it('flags an unprotected (without sharing) guest-executable class as CRITICAL', async () => {
    const ctx = makeCtx(
      {
        guestUsers: [{ Id: '005g', ProfileId: '00eP0000000AbCdEAA', Username: 'guest@site' }],
        setupAccess: [{ SetupEntityId: '01pA0000000AbCdEAA', ParentId: '0PSP0000000AbCdEAA' }],
        apexNames: [{ Id: '01pA0000000AbCdEAA', Name: 'PublicController' }],
      },
      [{ name: 'PublicController', body: 'public without sharing class PublicController { void f(){ [SELECT Id FROM Account]; } }' }],
    );
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('PublicController');
  });

  it('flags guest-executable classes (no body available) as HIGH exposed', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP0000000AbCdEAA', Username: 'guest@site' }],
      setupAccess: [{ SetupEntityId: '01pA0000000AbCdEAA', ParentId: '0PSP0000000AbCdEAA' }],
      apexNames: [{ Id: '01pA0000000AbCdEAA', Name: 'SomeController' }],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-exposed');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('passes when guests can execute no Apex classes', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP0000000AbCdEAA', Username: 'guest@site' }],
      setupAccess: [],
      apexNames: [],
    });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-ok' && f.passed)).toBe(true);
  });

  // SetupEntityAccess.ParentId holds permission set Ids; filtering it by profile Id matches nothing.
  it('reads class access through the guests\' permission sets, never by profile Id', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP0000000AbCdEAA', Username: 'guest@site' }],
      setupAccess: [], apexNames: [],
    });
    await check.run(ctx);
    const calls = (ctx.soql.queryAll as any).mock.calls.map((c: any) => c[0] as string);
    expect(calls[1]).toMatch(/FROM PermissionSetAssignment WHERE AssigneeId IN \('005g'\)/);
    const sea = calls.find((q: string) => /SetupEntityAccess/.test(q))!;
    expect(sea).toContain("'0PSP0000000AbCdEAA'");
    expect(sea).not.toContain('00eP');
  });

  // spec RULE-007: from API 67.0 an omitted sharing keyword means with sharing.
  describe('API 67.0 sharing default', () => {
    const guest = { Id: '005g', ProfileId: '00eP0000000AbCdEAA', Username: 'guest@site' };
    const run = (classes: Array<{ name: string; body: string; v: number }>) => {
      const ctx = makeCtx(
        {
          guestUsers: [guest],
          setupAccess: [{ SetupEntityId: '01pA0000000AbCdEAA', ParentId: '0PSP0000000AbCdEAA' }],
          apexNames: [{ Id: '01pA0000000AbCdEAA', Name: classes[0].name }],
        },
        classes.map(({ name, body }) => ({ name, body })),
      );
      (ctx.soql.queryAll as any).mockResolvedValueOnce(classes.map((c) => ({ Name: c.name, ApiVersion: c.v })));
      return check.run(ctx);
    };
    const ids = (r: { findings: Array<{ id: string }> }) => r.findings.map((f) => f.id);

    it('treats a keyword-less class at 67.0 as with sharing', async () => {
      const r = await run([{ name: 'Ctl', body: 'public class Ctl { }', v: 67 }]);
      expect(ids(r)).not.toContain('guest-executable-apex-unprotected');
      expect(ids(r)).toContain('guest-executable-apex-exposed');
    });

    it('keeps a keyword-less class below 67.0 unprotected', async () => {
      const r = await run([{ name: 'Ctl', body: 'public class Ctl { }', v: 66 }]);
      expect(r.findings.find((f) => f.id === 'guest-executable-apex-unprotected')!.affectedItems![0].note)
        .toContain('not shown to be saved at API 67.0 or later');
    });

    it('keeps it unprotected when a keyword-less parent is below 67.0', async () => {
      const r = await run([
        { name: 'Ctl', body: 'public class Ctl extends Base { }', v: 67 },
        { name: 'Base', body: 'public virtual class Base { }', v: 60 },
      ]);
      expect(ids(r)).toContain('guest-executable-apex-unprotected');
    });

    // RULE-007: a 67.0 keyword-less class is judged like a with-sharing one, helpers included.
    it('still follows a 67.0 class into a without-sharing helper', async () => {
      const ctx = makeCtx(
        {
          guestUsers: [guest],
          setupAccess: [{ SetupEntityId: '01pA0000000AbCdEAA', ParentId: '0PSP0000000AbCdEAA' }],
          apexNames: [{ Id: '01pA0000000AbCdEAA', Name: 'Ctl' }],
        },
        [
          { name: 'Ctl', body: 'public class Ctl { void f(){ Helper.go(); } }', symbolTable: { externalReferences: [{ name: 'Helper' }] } } as any,
          { name: 'Helper', body: 'public without sharing class Helper { }' },
        ],
      );
      (ctx.soql.queryAll as any).mockResolvedValueOnce([{ Name: 'Ctl', ApiVersion: 67 }, { Name: 'Helper', ApiVersion: 67 }]);
      const f = (await check.run(ctx)).findings.find((x) => x.id === 'guest-executable-apex-unprotected')!;
      expect(f.affectedItems![0].note).toBe('Reaches "Helper", which is declared "without sharing"');
    });

    // spec RULE-008: an Aura/LWC call into a keyword-less class runs with sharing.
    it('does not call a keyword-less class reached only from Aura unprotected, whatever its version', async () => {
      const r = await run([{ name: 'Ctl', body: 'public class Ctl { @AuraEnabled public static void go() {} }', v: 50 }]);
      expect(ids(r)).not.toContain('guest-executable-apex-unprotected');
      expect(ids(r)).toContain('guest-executable-apex-exposed');
    });

    it('keeps it unprotected when it is also a Visualforce controller', async () => {
      const r = await run([{ name: 'Ctl', body: 'public class Ctl { @AuraEnabled public static void go() {} public PageReference save() { return null; } }', v: 50 }]);
      expect(r.findings.find((f) => f.id === 'guest-executable-apex-unprotected')!.affectedItems![0].note)
        .toContain('REST, SOAP, remoting, a flow action or a Visualforce page');
    });

    it('keeps the old default when versions cannot be read', async () => {
      const ctx = makeCtx(
        {
          guestUsers: [guest],
          setupAccess: [{ SetupEntityId: '01pA0000000AbCdEAA', ParentId: '0PSP0000000AbCdEAA' }],
          apexNames: [{ Id: '01pA0000000AbCdEAA', Name: 'Ctl' }],
        },
        [{ name: 'Ctl', body: 'public class Ctl { }' }],
      );
      (ctx.soql.queryAll as any).mockRejectedValueOnce(new Error('INVALID_TYPE'));
      expect(ids(await check.run(ctx))).toContain('guest-executable-apex-unprotected');
    });
  });
});
