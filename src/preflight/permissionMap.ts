import type { AuditCache } from '@cclabsnz/sf-core';
import type { SecurityCheck } from '../checks/SecurityCheck.js';
import { CHECKS } from '../checks/registry.js';

export type AuditPermission =
  | 'ApiEnabled'
  | 'ViewSetup'
  | 'ViewAllUsers'
  | 'ViewHealthCheckScreen'
  | 'AuthorApex'
  | 'ViewEventLogFiles';

export interface PermissionSpec {
  /** Field on UserPermissionAccess carrying the effective grant. */
  readonly field: string;
  readonly label: string;
  /** What the audit loses without it. */
  readonly impact: string;
  /**
   * Cache keys whose producers and consumers need this permission. The affected
   * check list is derived from the registry via these keys rather than hand-written,
   * so a check added later is covered without touching this file.
   *
   * Empty for permissions too broad to attribute to specific checks.
   */
  readonly cacheKeys: ReadonlyArray<keyof AuditCache>;
  /** The audit cannot run at all without this. */
  readonly blocking?: boolean;
}

export const AUDIT_PERMISSIONS: Readonly<Record<AuditPermission, PermissionSpec>> = {
  ApiEnabled: {
    field: 'PermissionsApiEnabled',
    label: 'API Enabled',
    impact: 'All access is via SOQL/Tooling/REST. Without it the audit cannot run at all.',
    cacheKeys: [],
    blocking: true,
  },
  ViewSetup: {
    field: 'PermissionsViewSetup',
    label: 'View Setup and Configuration',
    impact:
      'Reads the bulk of the surface — connected apps, remote sites, CSP, named credentials, auth config, ' +
      'Experience sites, and Tooling metadata. Most setup and configuration checks return inconclusive without it.',
    cacheKeys: [],
  },
  ViewAllUsers: {
    field: 'PermissionsViewAllUsers',
    label: 'View All Users',
    impact:
      'Enumerates every User, PermissionSetAssignment and TwoFactorInfo org-wide. Without it the user, ' +
      'admin and MFA checks under-count and miss accounts outside the role hierarchy.',
    cacheKeys: ['mfaRegistrations', 'effectivePermissions'],
  },
  ViewHealthCheckScreen: {
    field: 'PermissionsViewHealthCheck',
    label: 'View Health Check',
    impact: 'Reads SecurityHealthCheck and its risks. Health Check and password/session baselines are inconclusive without it.',
    cacheKeys: ['healthCheckRisks'],
  },
  AuthorApex: {
    field: 'PermissionsAuthorApex',
    label: 'Author Apex (read-only use)',
    impact:
      'The only standard gate exposing ApexClass/ApexTrigger/ApexPage Body via the Tooling API. ' +
      'Grants no ability to modify org data. The code-security checks are inconclusive without it.',
    cacheKeys: ['apexBodies', 'vfPageBodies'],
  },
  ViewEventLogFiles: {
    field: 'PermissionsViewEventLogFiles',
    label: 'View Event Log Files',
    impact: 'Reads EventLogFile. Whether login and API activity is monitored cannot be established without it.',
    cacheKeys: ['eventLogSummary'],
  },
};

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

const usesKey = (check: SecurityCheck, key: keyof AuditCache): boolean =>
  (check.dependsOnCache?.includes(key) ?? false) || (check.populatesCache?.includes(key) ?? false);

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
