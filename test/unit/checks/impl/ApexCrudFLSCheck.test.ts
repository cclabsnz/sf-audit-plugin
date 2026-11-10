import { ApexCrudFLSCheck } from '../../../../src/checks/impl/ApexCrudFLSCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const ctxWith = (body: string): AuditContext => ({
  soql: {}, tooling: {}, rest: {},
  orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
  cache: { apexBodies: [{ name: 'Leaky', body }] },
} as unknown as AuditContext);

describe('ApexCrudFLSCheck', () => {
  // "with sharing" enforces record sharing only, so the CRUD/FLS finding must lead with the CRUD/FLS
  // remedy and must not read as a duplicate of the sharing finding.
  it('leads the without-sharing CRUD/FLS remedy with object and field enforcement', async () => {
    const r = await new ApexCrudFLSCheck().run(ctxWith(
      'public without sharing class Leaky { public static void go() { List<Account> a = [SELECT Id FROM Account]; update a; } }',
    ));
    const f = r.findings.find((x) => x.id === 'apex-crud-fls-without-sharing')!;
    expect(f.remediation.startsWith('Enforce object and field permissions with `WITH USER_MODE`')).toBe(true);
    expect(f.remediation).toContain('"with sharing" alone does not do this');
  });

  // spec RULE-009: from API 67.0 queries and DML run in user mode by default.
  describe('API 67.0 user mode default', () => {
    const withVersion = (body: string, v: number | Error) => ({
      ...ctxWith(body),
      soql: { queryAll: async () => { if (v instanceof Error) throw v; return [{ Name: 'Leaky', ApiVersion: v }]; } },
    } as unknown as AuditContext);
    const ids = (r: { findings: Array<{ id: string }> }) => r.findings.map((f) => f.id);
    const DML = 'public with sharing class Leaky { public static void go() { List<Account> a = [SELECT Id FROM Account]; update a; } }';

    it('does not report a 67.0 class for missing CRUD/FLS checks', async () => {
      const r = await new ApexCrudFLSCheck().run(withVersion(DML, 67));
      expect(ids(r)).toEqual(['apex-crud-fls-ok']);
      expect((r.findings[0] as { detail: string }).detail).toContain('1 class(es) saved at API 67.0 or later rely on user mode');
    });

    it('reports it below 67.0, or when versions cannot be read', async () => {
      expect(ids(await new ApexCrudFLSCheck().run(withVersion(DML, 66)))).toContain('apex-crud-fls-missing');
      expect(ids(await new ApexCrudFLSCheck().run(withVersion(DML, new Error('x'))))).toContain('apex-crud-fls-missing');
    });

    it('still reports SYSTEM_MODE in a 67.0 class', async () => {
      const r = await new ApexCrudFLSCheck().run(withVersion(DML.replace('FROM Account]', 'FROM Account WITH SYSTEM_MODE]'), 67));
      expect(ids(r)).toContain('apex-crud-fls-system-mode');
    });
  });
});
