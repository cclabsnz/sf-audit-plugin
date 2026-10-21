import type { SecurityCheck } from '../checks/SecurityCheck.js';
import { CHECKS } from '../checks/registry.js';

export { AUDIT_PERMISSIONS, type AuditPermission, type PermissionSpec } from './permissions.js';
import { AUDIT_PERMISSIONS, usesKey, type AuditPermission } from './permissions.js';

export interface MissingPermission {
  permission: AuditPermission;
  label: string;
  impact: string;
  blocking: boolean;
  affectedChecks: string[];
}

export interface PreflightResult {
  canRun: boolean;
  granted: AuditPermission[];
  missing: MissingPermission[];
  /** Checks expected to produce a verdict. */
  willRun: number;
  /** Checks expected to return inconclusive, deduplicated across permissions. */
  willBeInconclusive: string[];
}

/** Check ids that need `permission`, derived from the registry's declared cache wiring. */
export function checksRequiring(permission: AuditPermission, checks: readonly SecurityCheck[] = CHECKS): string[] {
  const { cacheKeys } = AUDIT_PERMISSIONS[permission];
  if (cacheKeys.length === 0) return [];
  return checks.filter((c) => cacheKeys.some((k) => usesKey(c, k))).map((c) => c.id);
}

/**
 * What this audit user will and will not be able to establish, before spending a run.
 *
 * The tool can only report a permission gap after the audit has already come back
 * blind; this answers the same question up front, when it is still cheap to fix.
 */
export function buildPreflight(
  granted: Record<AuditPermission, boolean>,
  checks: readonly SecurityCheck[] = CHECKS,
): PreflightResult {
  const permissions = Object.keys(AUDIT_PERMISSIONS) as AuditPermission[];
  const missing: MissingPermission[] = [];
  const inconclusive = new Set<string>();

  for (const permission of permissions) {
    if (granted[permission]) continue;
    const spec = AUDIT_PERMISSIONS[permission];
    const affectedChecks = checksRequiring(permission, checks);
    affectedChecks.forEach((id) => inconclusive.add(id));
    missing.push({
      permission,
      label: spec.label,
      impact: spec.impact,
      blocking: spec.blocking === true,
      affectedChecks,
    });
  }

  return {
    canRun: !missing.some((m) => m.blocking),
    granted: permissions.filter((p) => granted[p]),
    missing,
    willRun: checks.length - inconclusive.size,
    willBeInconclusive: [...inconclusive],
  };
}
