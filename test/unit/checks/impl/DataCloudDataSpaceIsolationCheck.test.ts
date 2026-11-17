import { jest } from '@jest/globals';
import { DataCloudDataSpaceIsolationCheck } from '../../../../src/checks/impl/DataCloudDataSpaceIsolationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(soql: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soql)) {
          if (q.includes(key)) return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: '00D000000000001',
      name: 'Test Org',
      type: 'Developer Edition',
      isSandbox: false,
      instance: 'NA1',
      instanceUrl: 'https://test.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const psa = (userId: string, userType: string, username: string, psName: string) => ({
  Id: `0Pa${userId}${psName}`,
  AssigneeId: userId,
  Assignee: { Username: username, UserType: userType },
  PermissionSet: { Name: psName, Label: psName },
});
const defaultSpace = [{ Id: '0vS1', Name: 'default' }];

describe('DataCloudDataSpaceIsolationCheck', () => {
  const check = new DataCloudDataSpaceIsolationCheck();

  it('passes when Data Cloud is not enabled', async () => {
    const r = await check.run(makeCtx({ 'FROM DataSpace': new Error("sObject type 'DataSpace' is not supported.") }));
    expect(r.findings.map((f) => f.id)).toEqual(['data-cloud-data-space-not-enabled']);
  });

  it('flags a partner user holding a Data Cloud permission set, counted once', async () => {
    const r = await check.run(
      makeCtx({
        'FROM DataSpace': defaultSpace,
        'FROM PermissionSetAssignment': [
          psa('005A', 'PowerPartner', 'p1@partner.example', 'DataCloudUser'),
          psa('005A', 'PowerPartner', 'p1@partner.example', 'DataSpace_Default'),
        ],
      }),
    );
    const f = r.findings.find((x) => x.id === 'data-cloud-data-space-default-overshared');
    expect(f?.affectedItems).toHaveLength(1);
    expect(f?.title).toMatch(/^1 /);
  });

  it('ignores external users whose permission sets have nothing to do with Data Cloud', async () => {
    const r = await check.run(
      makeCtx({
        'FROM DataSpace': defaultSpace,
        'FROM PermissionSetAssignment': [psa('005B', 'PowerPartner', 'p2@partner.example', 'Partner_Community_Extras')],
      }),
    );
    expect(r.findings.map((f) => f.id)).toEqual(['data-cloud-data-space-ok']);
  });

  it('ignores internal users with Data Cloud access', async () => {
    const r = await check.run(
      makeCtx({
        'FROM DataSpace': defaultSpace,
        'FROM PermissionSetAssignment': [psa('005C', 'Standard', 'analyst@corp.example', 'DataCloudUser')],
      }),
    );
    expect(r.findings.map((f) => f.id)).toEqual(['data-cloud-data-space-ok']);
  });

  it('does not flag when there is no default data space', async () => {
    const r = await check.run(
      makeCtx({
        'FROM DataSpace': [{ Id: '0vS2', Name: 'Partners' }],
        'FROM PermissionSetAssignment': [psa('005D', 'PowerPartner', 'p3@partner.example', 'DataCloudUser')],
      }),
    );
    expect(r.findings.some((f) => f.id === 'data-cloud-data-space-default-overshared')).toBe(false);
  });

  it('propagates a permission error on PermissionSetAssignment instead of passing', async () => {
    await expect(
      check.run(makeCtx({ 'FROM DataSpace': defaultSpace, 'FROM PermissionSetAssignment': new Error('INSUFFICIENT_ACCESS') })),
    ).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('propagates a permission error on ExtDataShare instead of passing', async () => {
    await expect(
      check.run(makeCtx({ 'FROM DataSpace': defaultSpace, 'FROM ExtDataShare': new Error('INSUFFICIENT_ACCESS') })),
    ).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('treats a missing ExtDataShare object as no shares', async () => {
    const r = await check.run(
      makeCtx({ 'FROM DataSpace': defaultSpace, 'FROM ExtDataShare': new Error("sObject type 'ExtDataShare' is not supported.") }),
    );
    expect(r.findings.map((f) => f.id)).toEqual(['data-cloud-data-space-ok']);
  });

  it('lists outbound data shares as a LOW review item, without claiming they are unconstrained', async () => {
    const ctx = makeCtx({
      'FROM DataSpace': defaultSpace,
      'FROM ExtDataShare': [{ Id: '0ds1', Name: 'Orders_to_Snowflake', DataShareType: 'Outbound', ObjectCount: 3, DataSpace: { Name: 'default' } }],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'data-cloud-outbound-data-shares');
    expect(f?.riskLevel).toBe('INFO');
    expect(f?.title).not.toMatch(/unconstrained|without/i);
    expect(f?.affectedItems?.[0].note).toContain('objects: 3');
    const q = ((ctx.soql.queryAll as any).mock.calls as string[][]).map((c) => c[0]).find((x) => x.includes('ExtDataShare'));
    expect(q).toContain("DataShareType = 'Outbound'");
    expect(r.findings.some((x) => x.id === 'data-cloud-data-share-target-unconstrained')).toBe(false);
  });

  it('says the default-space finding is a name-based signal, at MEDIUM', async () => {
    const r = await check.run(
      makeCtx({ 'FROM DataSpace': defaultSpace, 'FROM PermissionSetAssignment': [psa('005E', 'PowerPartner', 'p4@partner.example', 'DataCloudUser')] }),
    );
    const f = r.findings.find((x) => x.id === 'data-cloud-data-space-default-overshared');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f?.detail).toMatch(/name-based/i);
  });
});
