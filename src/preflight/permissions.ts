import type { AuditCache } from '@cclabsnz/sf-core';
import type { SecurityCheck } from '../checks/SecurityCheck.js';

// The permission table, kept apart from permissionMap.ts so CheckEngine can name a check's
// permissions without importing the check registry.

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

export const usesKey = (check: SecurityCheck, key: keyof AuditCache): boolean =>
  (check.dependsOnCache?.includes(key) ?? false) || (check.populatesCache?.includes(key) ?? false);

/** Labels of the permissions this check's declared cache wiring needs; empty when none is attributable. */
export function permissionLabelsFor(check: SecurityCheck): string[] {
  return (Object.values(AUDIT_PERMISSIONS) as PermissionSpec[])
    .filter((spec) => spec.cacheKeys.some((k) => usesKey(check, k)))
    .map((spec) => spec.label);
}
