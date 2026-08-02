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
  const psIds = [...new Set(psa.map((p) => p.PermissionSetId))];
  if (psIds.length === 0) return { appId, scope, objects: [], runAsUsers, multiUserInteractive };

  const perms = await soql
    .queryAll<ObjPermRow>(
      `SELECT ParentId, SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete
       FROM ObjectPermissions WHERE ParentId IN (${inList(psIds)}) AND PermissionsRead = true`,
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
