import type { SoqlClient } from '@cclabsnz/sf-core';
import { AUDIT_PERMISSIONS, type AuditPermission } from './permissionMap.js';

type PermissionRow = Record<string, boolean | undefined>;

/**
 * The running user's *effective* permissions — profile unioned with every assigned
 * permission set — in one read.
 *
 * UserPermissionAccess returns exactly one row scoped to the caller, so this needs no
 * assignment join and no aggregation. Read-only, like everything else here.
 */
export async function readEffectivePermissions(soql: SoqlClient): Promise<Record<AuditPermission, boolean>> {
  const permissions = Object.keys(AUDIT_PERMISSIONS) as AuditPermission[];
  const fields = permissions.map((p) => AUDIT_PERMISSIONS[p].field);
  const result = await soql.query<PermissionRow>(`SELECT ${fields.join(', ')} FROM UserPermissionAccess`);
  const row = result.records[0] ?? {};

  const granted = {} as Record<AuditPermission, boolean>;
  for (const permission of permissions) {
    granted[permission] = row[AUDIT_PERMISSIONS[permission].field] === true;
  }
  return granted;
}
