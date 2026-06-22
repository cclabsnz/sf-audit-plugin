// Shared vocabulary of high-risk Salesforce user permissions, used by the
// access-control checks (PrivilegedAccessCheck builds the effective-permission
// cache from these; SeparationOfDutiesCheck reasons over combinations of them).
//
// IMPORTANT: every `field` below is a PermissionSet.Permissions* API name that is
// already queried elsewhere in this codebase (EscalationPermsCheck, UsersAndAdmins,
// ApiClientPermission), so it is known-valid. A single invalid field name would
// make the whole PermissionSetAssignment query fail with INVALID_FIELD.

export type PermTier = 'CRITICAL' | 'HIGH' | 'MEDIUM';

export interface DangerousPerm {
  /** Stable short key used in the effective-permission cache and combo rules. */
  key: string;
  /** PermissionSet.Permissions* API field name. */
  field: string;
  /** Human-readable label. */
  label: string;
  tier: PermTier;
  /** One-line abuse rationale. */
  why: string;
}

export const DANGEROUS_PERMS: DangerousPerm[] = [
  { key: 'ModifyAllData', field: 'PermissionsModifyAllData', label: 'Modify All Data', tier: 'CRITICAL',
    why: 'Read, edit, and delete every record in the org, bypassing sharing.' },
  { key: 'ManageUsers', field: 'PermissionsManageUsers', label: 'Manage Users', tier: 'CRITICAL',
    why: 'Create users and reset passwords — a direct account-takeover lever.' },
  { key: 'ViewAllData', field: 'PermissionsViewAllData', label: 'View All Data', tier: 'HIGH',
    why: 'Read every record in the org, bypassing sharing — mass data exposure.' },
  { key: 'AuthorApex', field: 'PermissionsAuthorApex', label: 'Author Apex', tier: 'HIGH',
    why: 'Deploy and run arbitrary Apex, which executes without sharing by default.' },
  { key: 'CustomizeApplication', field: 'PermissionsCustomizeApplication', label: 'Customize Application', tier: 'HIGH',
    why: 'Change org metadata and configuration, including security settings.' },
  { key: 'ModifyMetadata', field: 'PermissionsModifyMetadata', label: 'Modify Metadata', tier: 'HIGH',
    why: 'Change metadata via the API, enabling stealthy configuration tampering.' },
  { key: 'ManageInternalUsers', field: 'PermissionsManageInternalUsers', label: 'Manage Internal Users', tier: 'HIGH',
    why: 'Administer internal user accounts, including password resets.' },
  { key: 'AssignPermissionSets', field: 'PermissionsAssignPermissionSets', label: 'Assign Permission Sets', tier: 'HIGH',
    why: 'Grant permission sets — can be used to self-escalate to any access.' },
  { key: 'ManageAuthProviders', field: 'PermissionsManageAuthProviders', label: 'Manage Auth. Providers', tier: 'HIGH',
    why: 'Control SSO / auth providers, enabling identity-provider takeover.' },
  { key: 'ManageConnectedApps', field: 'PermissionsManageConnectedApps', label: 'Manage Connected Apps', tier: 'HIGH',
    why: 'Control OAuth connected apps, a persistent external-access channel.' },
  { key: 'UseAnyApiClient', field: 'PermissionsUseAnyApiClient', label: 'Use Any API Client', tier: 'HIGH',
    why: 'Bypass API Access Control to reach the org from any tool.' },
  { key: 'ManageEventLogFiles', field: 'PermissionsManageEventLogFiles', label: 'Manage Event Log Files', tier: 'MEDIUM',
    why: 'Access detailed monitoring/event data across the org.' },
  { key: 'ManageSession', field: 'PermissionsManageSession', label: 'Manage Session Permission Set Activations', tier: 'MEDIUM',
    why: 'Activate session-based permission sets, elevating access on demand.' },
  { key: 'ViewAllUsers', field: 'PermissionsViewAllUsers', label: 'View All Users', tier: 'MEDIUM',
    why: 'Enumerate every user in the org — reconnaissance for targeting.' },
  { key: 'PasswordNeverExpires', field: 'PermissionsPasswordNeverExpires', label: 'Password Never Expires', tier: 'MEDIUM',
    why: 'Exempt the account from password rotation, weakening credential hygiene.' },
];

export const PERM_BY_KEY: Record<string, DangerousPerm> = Object.fromEntries(
  DANGEROUS_PERMS.map((p) => [p.key, p]),
);
