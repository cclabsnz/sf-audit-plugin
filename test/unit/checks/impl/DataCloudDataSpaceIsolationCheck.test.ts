import { jest } from '@jest/globals';
import { DataCloudDataSpaceIsolationCheck } from '../../../../src/checks/impl/DataCloudDataSpaceIsolationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(soqlResponses: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlResponses)) {
          if (new RegExp(`\\bFROM\\s+${key}\\b`, 'i').test(q)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
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

describe('DataCloudDataSpaceIsolationCheck', () => {
  const check = new DataCloudDataSpaceIsolationCheck();

  it('passes when DataSpace is not enabled (sObject not supported)', async () => {
    const err = new Error("sObject type 'DataSpace' is not supported.");
    const ctx = makeCtx({ DataSpace: err });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('data-cloud-data-space-not-enabled');
    expect(r.findings[0].passed).toBe(true);
  });

  it('reports inconclusive when DataSpace query errors', async () => {
    const ctx = makeCtx({ DataSpace: new Error('ACCESS_DENIED') });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('data-cloud-data-space-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when no DataSpace records exist', async () => {
    const ctx = makeCtx({ DataSpace: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('data-cloud-data-space-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags default DataSpace oversharing to partner or agent accounts', async () => {
    const ctx = makeCtx({
      DataSpace: [{ Id: '0ds1', Name: 'default', IsDefault: true }],
      PermissionSetAssignment: [
        {
          Id: '0pa1',
          AssigneeId: '005p1',
          Assignee: { Username: 'partner@portal.com', UserType: 'PowerPartner' },
          PermissionSet: { Name: 'DataCloudUser' },
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'data-cloud-data-space-default-overshared');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags active unconstrained DataShareTarget records', async () => {
    const ctx = makeCtx({
      DataSpace: [{ Id: '0ds2', Name: 'SegmentA', IsDefault: false }],
      DataShareTarget: [{ Id: '0st1', Name: 'SnowflakeTarget', TargetType: 'Snowflake', Status: 'Active' }],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'data-cloud-data-share-target-unconstrained');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('passes when data spaces are segmented and targets are inactive', async () => {
    const ctx = makeCtx({
      DataSpace: [{ Id: '0ds2', Name: 'SegmentA', IsDefault: false }],
      PermissionSetAssignment: [],
      DataShareTarget: [{ Id: '0st1', Name: 'SnowflakeTarget', TargetType: 'Snowflake', Status: 'Inactive' }],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('data-cloud-data-space-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
