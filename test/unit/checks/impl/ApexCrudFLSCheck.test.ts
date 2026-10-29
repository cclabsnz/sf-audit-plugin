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
});
