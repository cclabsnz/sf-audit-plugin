import { jest } from '@jest/globals';
import { PlatformEventSubscriberContextCheck } from '../../../../src/checks/impl/PlatformEventSubscriberContextCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(toolingData: Record<string, unknown[] | Error>, soqlData: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(toolingData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
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

describe('PlatformEventSubscriberContextCheck', () => {
  const check = new PlatformEventSubscriberContextCheck();

  it('passes when no triggers on custom Platform Events exist', async () => {
    const ctx = makeCtx({ ApexTrigger: [{ Id: '01q1', Name: 'AccountTrigger', TableEnumOrId: 'Account', Status: 'Active' }] }, {});
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('platform-event-subscriber-context-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('marks inconclusive when Tooling query fails', async () => {
    const ctx = makeCtx({ ApexTrigger: new Error('TOOLING_ERROR') }, {});
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('platform-event-subscriber-context-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('flags escalation when low-trust profile has Create access to an event triggering Automated Process subscriber', async () => {
    const ctx = makeCtx(
      {
        ApexTrigger: [{ Id: '01q2', Name: 'OrderEventTrigger', TableEnumOrId: 'Order_Event__e', Status: 'Active' }],
        PlatformEventSubscriberConfig: [],
      },
      {
        Profile: [{ Id: '00eGuest', Name: 'Store Guest Profile', UserType: 'Guest' }],
        ObjectPermissions: [
          {
            Id: '0op1',
            ParentId: '00eGuest',
            SobjectType: 'Order_Event__e',
            PermissionsCreate: true,
            Parent: { IsOwnedByProfile: true, Profile: { Name: 'Store Guest Profile', UserType: 'Guest' } },
          },
        ],
      },
    );
    const r = await check.run(ctx);
    const escalationFinding = r.findings.find((f) => f.id === 'platform-event-subscriber-escalation');
    expect(escalationFinding).toBeDefined();
    expect(escalationFinding?.riskLevel).toBe('CRITICAL');
  });

  it('passes when no low-trust publisher exists for event triggers', async () => {
    const ctx = makeCtx(
      {
        ApexTrigger: [{ Id: '01q3', Name: 'InternalEventTrigger', TableEnumOrId: 'Internal_Event__e', Status: 'Active' }],
        PlatformEventSubscriberConfig: [],
      },
      {
        Profile: [{ Id: '00eGuest', Name: 'Guest Profile', UserType: 'Guest' }],
        ObjectPermissions: [],
      },
    );
    const r = await check.run(ctx);
    const okFinding = r.findings.find((f) => f.id === 'platform-event-subscriber-context-ok');
    expect(okFinding).toBeDefined();
    expect(okFinding?.passed).toBe(true);
  });
});
