import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { GuestUserAccessCheck } from '../../../src/checks/impl/GuestUserAccessCheck.js';
import { GuestObjectExposureCheck } from '../../../src/checks/impl/GuestObjectExposureCheck.js';

// Both guest checks run on the same org. A guest read on Account, Case, Contact or Opportunity is
// GuestUserAccessCheck's to report; GuestObjectExposureCheck reports only guest-owned records there.
// One exposure must be one finding, whichever way it shows (share rows, or UserRecordAccess alone).
function org(opts: { owd: string; shareRows: number; owned: number }): AuditContext {
  const queryAll = jest.fn(async (q: string) => {
    if (/FROM User WHERE UserType = 'Guest'/.test(q)) return [{ Id: '005G', ProfileId: '00eG', Username: 'guest' }];
    if (/FROM PermissionSetAssignment/.test(q)) return [{ AssigneeId: '005G', PermissionSetId: '0PSG' }];
    if (/FROM ObjectPermissions/.test(q)) {
      return [{ ParentId: '0PSG', SobjectType: 'Contact', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false }];
    }
    if (/FROM EntityDefinition/.test(q)) return [{ QualifiedApiName: 'Contact', ExternalSharingModel: opts.owd }];
    if (/FROM UserRecordAccess/.test(q)) return [{ RecordId: '003x', HasReadAccess: true }];
    return [];
  });
  const query = jest.fn(async (q: string) => {
    if (/FROM ContactShare/.test(q)) return { records: [], totalSize: opts.shareRows, done: true };
    if (/FROM Contact WHERE OwnerId/.test(q)) return { records: [], totalSize: opts.owned, done: true };
    if (/^SELECT Id FROM Contact (ORDER BY SystemModstamp \w+ )?LIMIT/.test(q)) return { records: [{ Id: '003x' }], totalSize: 1, done: true };
    return { records: [], totalSize: 0, done: true };
  });
  return {
    soql: { query, queryAll } as any,
    tooling: {} as any,
    rest: { get: async () => ({}) } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as unknown as AuditContext;
}

const EXPOSURE = /^(guest-user-sharing-exposure|guest-object-exposure-(guest-shared|public-owd|guest-owned))$/;

describe('a guest exposure on a standard object is reported once', () => {
  it.each([
    ['share rows, Private OWD', { owd: 'Private', shareRows: 3, owned: 0 }, 'guest-user-sharing-exposure'],
    ['share rows, public OWD', { owd: 'Read', shareRows: 3, owned: 0 }, 'guest-user-sharing-exposure'],
    ['UserRecordAccess only, Private OWD', { owd: 'Private', shareRows: 0, owned: 0 }, 'guest-user-sharing-exposure'],
    ['UserRecordAccess only, public OWD', { owd: 'Read', shareRows: 0, owned: 0 }, 'guest-user-sharing-exposure'],
    ['guest-owned records', { owd: 'Private', shareRows: 0, owned: 2 }, 'guest-object-exposure-guest-owned'],
  ])('%s', async (_case, opts, expected) => {
    const ctx = org(opts);
    const ids = [
      ...(await new GuestUserAccessCheck().run(ctx)).findings,
      ...(await new GuestObjectExposureCheck().run(ctx)).findings,
    ].map((f) => f.id).filter((id) => EXPOSURE.test(id));
    expect(ids).toEqual([expected]);
  });
});
