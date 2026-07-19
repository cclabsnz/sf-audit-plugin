import { jest } from '@jest/globals';
import { AgentUserPrivilegeCheck } from '../../../../src/checks/impl/AgentUserPrivilegeCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';
import type { AgentUser } from '../../../../src/context/AuditCache.js';

// Route each query by the sObject it hits so a fixture can supply per-object records
// (or per-object errors) without depending on call order.
type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: {
  agentUsers?: AgentUser[];
  agentAccess?: 'ok' | 'not-enabled' | 'unknown';
  soql?: Handler;
  tooling?: Handler;
}): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((soql: string) =>
        opts.soql ? opts.soql(soql) : Promise.resolve([]),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((soql: string) =>
        opts.tooling ? opts.tooling(soql) : Promise.resolve([]),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'org1', name: 'Test', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://test.salesforce.com',
    },
    cache: {
      agentUsers: opts.agentUsers,
      agentAccess: opts.agentAccess,
    },
  } as any;
}

function apiError(errorCode: string, statusCode = 400): Error {
  return Object.assign(new Error(errorCode), { errorCode, statusCode });
}

function user(overrides: Partial<AgentUser>): AgentUser {
  return {
    userId: 'U1',
    username: 'agent@x.com',
    profileName: 'Einstein Agent User',
    isActive: true,
    permissionSetIds: ['PS1'],
    permissionSetLicenseNames: ['Agentforce'],
    ...overrides,
  };
}

describe('AgentUserPrivilegeCheck', () => {
  const check = new AgentUserPrivilegeCheck();

  it('declares its cache contract', () => {
    expect(check.id).toBe('agent-user-privilege');
    expect(check.category).toBe('AI & Agents');
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['agentUsers', 'agentAccess']),
    );
  });

  it('is silent when agentAccess is not ok (not-enabled)', async () => {
    const ctx = makeCtx({
      agentAccess: 'not-enabled',
      agentUsers: [user({})],
      soql: () => Promise.reject(new Error('should not be queried')),
    });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('is silent when agentAccess is unknown', async () => {
    const ctx = makeCtx({ agentAccess: 'unknown', agentUsers: [user({})] });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('is silent when there are no agent users', async () => {
    const ctx = makeCtx({ agentAccess: 'ok', agentUsers: [] });
    const result = await check.run(ctx);
    expect(result.findings).toHaveLength(0);
  });

  it('flags a CRITICAL for an agent user holding Modify All Data', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U1', username: 'super.agent@x.com', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          // PS1 grants ModifyAllData
          return Promise.resolve([
            { Id: 'PS1', Label: 'Agent Power', PermissionsModifyAllData: true, PermissionsViewAllData: false },
          ]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve([]);
        }
        return Promise.resolve([]);
      },
    });

    const result = await check.run(ctx);
    const crit = result.findings.filter((f) => f.riskLevel === 'CRITICAL');
    expect(crit).toHaveLength(1);
    expect(crit[0].id).toBe('agent-user-privilege-admin-U1');
    expect(crit[0].title).toContain('super.agent@x.com');
    expect(crit[0].detail).toContain('Modify All Data');
    expect(crit[0].affectedItems?.[0].note).toContain('Agent Power');
  });

  it('flags a CRITICAL for View All Data too', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U2', permissionSetIds: ['PS2'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([
            { Id: 'PS2', Label: 'Read Everything', PermissionsModifyAllData: false, PermissionsViewAllData: true },
          ]);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const crit = result.findings.filter((f) => f.riskLevel === 'CRITICAL');
    expect(crit).toHaveLength(1);
    expect(crit[0].detail).toContain('View All Data');
  });

  it('flags HIGH broad object write access at the threshold boundary (11 objects)', async () => {
    // 10 writable objects => no finding; 11 => finding. Test the crossing (11).
    const writableObjs = Array.from({ length: 11 }, (_, i) => ({
      ParentId: 'PS1',
      SobjectType: `Obj${i}__c`,
      PermissionsRead: true,
      PermissionsCreate: true,
      PermissionsEdit: true,
      PermissionsDelete: false,
    }));
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U3', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([{ Id: 'PS1', Label: 'Broad Writer', PermissionsModifyAllData: false, PermissionsViewAllData: false }]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve(writableObjs);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const high = result.findings.filter((f) => f.riskLevel === 'HIGH' && f.id.startsWith('agent-user-privilege-broad-write'));
    expect(high).toHaveLength(1);
    expect(high[0].id).toBe('agent-user-privilege-broad-write-U3');
    expect(high[0].detail).toContain('11');
  });

  it('does NOT flag broad write at 10 writable objects (at threshold, not over)', async () => {
    const writableObjs = Array.from({ length: 10 }, (_, i) => ({
      ParentId: 'PS1',
      SobjectType: `Obj${i}__c`,
      PermissionsRead: true,
      PermissionsCreate: true,
      PermissionsEdit: false,
      PermissionsDelete: false,
    }));
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U4', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([{ Id: 'PS1', Label: 'Ten Writer', PermissionsModifyAllData: false, PermissionsViewAllData: false }]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve(writableObjs);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const high = result.findings.filter((f) => f.id.startsWith('agent-user-privilege-broad-write'));
    expect(high).toHaveLength(0);
  });

  it('flags HIGH for read access to a sensitive/classified object', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U5', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([{ Id: 'PS1', Label: 'Reader', PermissionsModifyAllData: false, PermissionsViewAllData: false }]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve([
            { ParentId: 'PS1', SobjectType: 'Account', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
            { ParentId: 'PS1', SobjectType: 'Patient__c', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
          ]);
        }
        return Promise.resolve([]);
      },
      tooling: (soql) => {
        if (/FROM FieldDefinition/i.test(soql)) {
          // Patient__c has classified fields; Account does not appear here.
          return Promise.resolve([{ objectName: 'Patient__c', classifiedCount: 4 }]);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const sensitive = result.findings.filter((f) => f.id.startsWith('agent-user-privilege-sensitive-read'));
    expect(sensitive).toHaveLength(1);
    expect(sensitive[0].riskLevel).toBe('HIGH');
    expect(sensitive[0].detail).toContain('Patient__c');
    expect(sensitive[0].detail).not.toContain('Account');
  });

  it('silently skips the sensitive-read sub-signal when the org has no classification data', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U6', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([{ Id: 'PS1', Label: 'Reader', PermissionsModifyAllData: false, PermissionsViewAllData: false }]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve([
            { ParentId: 'PS1', SobjectType: 'Account', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
          ]);
        }
        return Promise.resolve([]);
      },
      tooling: (soql) => {
        if (/FROM FieldDefinition/i.test(soql)) {
          // No classification anywhere in the org.
          return Promise.resolve([]);
        }
        return Promise.resolve([]);
      },
    });
    const result = await check.run(ctx);
    const sensitive = result.findings.filter((f) => f.id.startsWith('agent-user-privilege-sensitive-read'));
    expect(sensitive).toHaveLength(0);
  });

  it('does not throw if the classification Tooling query errors (sub-signal degrades silently)', async () => {
    const ctx = makeCtx({
      agentAccess: 'ok',
      agentUsers: [user({ userId: 'U7', permissionSetIds: ['PS1'] })],
      soql: (soql) => {
        if (/FROM PermissionSet\b/i.test(soql)) {
          return Promise.resolve([{ Id: 'PS1', Label: 'Reader', PermissionsModifyAllData: false, PermissionsViewAllData: false }]);
        }
        if (/FROM ObjectPermissions/i.test(soql)) {
          return Promise.resolve([
            { ParentId: 'PS1', SobjectType: 'Account', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false },
          ]);
        }
        return Promise.resolve([]);
      },
      tooling: () => Promise.reject(apiError('INVALID_TYPE', 400)),
    });
    const result = await check.run(ctx);
    const sensitive = result.findings.filter((f) => f.id.startsWith('agent-user-privilege-sensitive-read'));
    expect(sensitive).toHaveLength(0);
  });
});
