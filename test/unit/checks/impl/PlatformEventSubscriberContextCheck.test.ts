import { jest } from '@jest/globals';
import { PlatformEventSubscriberContextCheck } from '../../../../src/checks/impl/PlatformEventSubscriberContextCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Shapes follow the platform, not the check's hopes: a trigger on a custom platform event has
// TableEnumOrId = the event's 01I Id (18 chars), EntityDefinition.DurableId is the 15-char form,
// and ObjectPermissions.ParentId is the profile-owned PermissionSet's 0PS Id, never a 00e Id.
function makeCtx(tooling: Record<string, unknown[] | Error>, soql: Record<string, unknown[] | Error>): AuditContext {
  const answer = (table: Record<string, unknown[] | Error>) =>
    (jest.fn() as any).mockImplementation((q: string) => {
      for (const [key, res] of Object.entries(table)) {
        if (q.includes(key)) return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
      }
      return Promise.resolve([]);
    });
  return {
    soql: { queryAll: answer(soql) } as any,
    tooling: { query: answer(tooling) } as any,
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

const EVENT_ID_18 = '01I5g000000AbCdEAF';
const EVENT_ID_15 = '01I5g000000AbCd';
const eventTrigger = { Id: '01q1', Name: 'OrderEventTrigger', TableEnumOrId: EVENT_ID_18, Status: 'Active' };
const eventDef = { DurableId: EVENT_ID_15, QualifiedApiName: 'Order_Placed__e' };
const guestProfile = { Id: '00e000000000GST', Name: 'Site Guest User', UserType: 'Guest' };
const guestPermSet = { Id: '0PS000000000GST', ProfileId: '00e000000000GST' };

describe('PlatformEventSubscriberContextCheck', () => {
  const check = new PlatformEventSubscriberContextCheck();

  it('passes when active triggers are only on standard objects', async () => {
    const ctx = makeCtx({ ApexTrigger: [{ Id: '01q2', Name: 'AccountTrigger', TableEnumOrId: 'Account', Status: 'Active' }] }, {});
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['platform-event-subscriber-context-ok']);
  });

  it('resolves a trigger Id to its __e event and flags guest publish access through the profile permission set', async () => {
    const ctx = makeCtx(
      { ApexTrigger: [eventTrigger], EntityDefinition: [eventDef] },
      {
        'FROM Profile': [guestProfile],
        'FROM PermissionSet': [guestPermSet],
        'FROM ObjectPermissions': [
          { Id: '110a', ParentId: '0PS000000000GST', SobjectType: 'Order_Placed__e', PermissionsCreate: true },
          { Id: '110b', ParentId: '0PS000000000INT', SobjectType: 'Order_Placed__e', PermissionsCreate: true },
        ],
      },
    );
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'platform-event-subscriber-escalation');
    expect(f?.riskLevel).toBe('CRITICAL');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['Order_Placed__e (Site Guest User)']);
  });

  it('passes when the subscribed event is publishable only by internal permission sets', async () => {
    const ctx = makeCtx(
      { ApexTrigger: [eventTrigger], EntityDefinition: [eventDef] },
      {
        'FROM Profile': [guestProfile],
        'FROM PermissionSet': [guestPermSet],
        'FROM ObjectPermissions': [{ Id: '110b', ParentId: '0PS000000000INT', SobjectType: 'Order_Placed__e', PermissionsCreate: true }],
      },
    );
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['platform-event-subscriber-context-ok']);
    expect(r.findings[0].detail).toContain('1 active');
  });

  it('does not flag guest Create on an event that has no active subscriber', async () => {
    const ctx = makeCtx(
      { ApexTrigger: [eventTrigger], EntityDefinition: [eventDef] },
      {
        'FROM Profile': [guestProfile],
        'FROM PermissionSet': [guestPermSet],
        'FROM ObjectPermissions': [{ Id: '110c', ParentId: '0PS000000000GST', SobjectType: 'Other_Event__e', PermissionsCreate: true }],
      },
    );
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.id === 'platform-event-subscriber-escalation')).toBe(false);
  });

  it('propagates a permission error on ApexTrigger instead of passing', async () => {
    const ctx = makeCtx({ ApexTrigger: new Error('INSUFFICIENT_ACCESS: ApexTrigger') }, {});
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('propagates a permission error on ObjectPermissions instead of passing', async () => {
    const ctx = makeCtx(
      { ApexTrigger: [eventTrigger], EntityDefinition: [eventDef] },
      { 'FROM Profile': [guestProfile], 'FROM PermissionSet': [guestPermSet], 'FROM ObjectPermissions': new Error('INSUFFICIENT_ACCESS') },
    );
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });
});
