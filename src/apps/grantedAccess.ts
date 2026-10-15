import type { GrantedAccess, Verb } from './types.js';
import type { SoqlClient } from '@cclabsnz/sf-core';

interface PsaRow { AssigneeId: string; PermissionSetId: string }
interface ObjPermRow {
  ParentId: string; SobjectType: string;
  PermissionsRead: boolean; PermissionsCreate: boolean; PermissionsEdit: boolean; PermissionsDelete: boolean;
}

const inList = (ids: string[]) => ids.map((i) => `'${i}'`).join(',');

export async function computeGranted(
  appId: string,
  runAsUsers: string[],
  soql: SoqlClient,
  scope: string | null,
): Promise<GrantedAccess> {
  const multiUserInteractive = runAsUsers.length > 3;
  if (runAsUsers.length === 0 || multiUserInteractive) {
    return { appId, scope, objects: [], runAsUsers, multiUserInteractive };
  }

  const psa = await soql
    .queryAll<PsaRow>(`SELECT AssigneeId, PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId IN (${inList(runAsUsers)})`)
    .catch(() => []);
  const psIds = new Set(psa.map((p) => p.PermissionSetId));

  // Query Profile-owned permission sets to unify profile-level ObjectPermissions
  interface UserProfileRow { Id: string; ProfileId: string }
  const users = await soql
    .queryAll<UserProfileRow>(`SELECT Id, ProfileId FROM User WHERE Id IN (${inList(runAsUsers)})`)
    .catch(() => []);
  const profileIds = [...new Set(users.map((u) => u.ProfileId).filter(Boolean))];

  if (profileIds.length > 0) {
    interface ProfilePsRow { Id: string; ProfileId: string }
    const profilePs = await soql
      .queryAll<ProfilePsRow>(`SELECT Id, ProfileId FROM PermissionSet WHERE IsOwnedByProfile = true AND ProfileId IN (${inList(profileIds)})`)
      .catch(() => []);
    for (const p of profilePs) {
      psIds.add(p.Id);
    }
  }

  const allPsIds = [...psIds];
  if (allPsIds.length === 0) return { appId, scope, objects: [], runAsUsers, multiUserInteractive };

  const perms = await soql
    .queryAll<ObjPermRow>(
      `SELECT ParentId, SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete
       FROM ObjectPermissions WHERE ParentId IN (${inList(allPsIds)}) AND PermissionsRead = true`,
    )
    .catch(() => []);

  const byObject = new Map<string, Set<Verb>>();
  for (const p of perms) {
    const verbs = byObject.get(p.SobjectType) ?? new Set<Verb>();
    if (p.PermissionsRead) verbs.add('read');
    if (p.PermissionsCreate || p.PermissionsEdit) verbs.add('write');
    if (p.PermissionsDelete) verbs.add('delete');
    byObject.set(p.SobjectType, verbs);
  }

  return {
    appId,
    scope,
    objects: [...byObject.entries()].map(([object, verbs]) => ({ object, verbs: [...verbs].sort() })),
    runAsUsers,
    multiUserInteractive,
  };
}
