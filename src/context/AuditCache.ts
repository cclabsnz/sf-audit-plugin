// HealthCheckRisk: one row from the Salesforce Health Check API
export interface HealthCheckRisk {
  setting: string;
  riskType: string;
  value: string;
  score: number;
}

// ApexClassBody: the subset of ApexClass fields checks need for scanning
export interface ApexClassBody {
  name: string;
  body: string;
}

// VfPageBody: Visualforce page markup, populated by VisualforceXssCheck
export interface VfPageBody {
  name: string;
  markup: string;
}

// Why an EventLogFile query failed: the feature is not licensed/enabled, or the
// running (audit) user lacks the "View Event Log Files" permission.
export type EventLogAccess = 'no-permission' | 'not-enabled' | 'unknown';

// EventLogSummary: populated by EventMonitoringCheck, consumed by SiemIntegrationCheck
// and GuestTrafficAnomalyCheck.
export interface EventLogSummary {
  earliestDate: string | null;
  totalFiles: number;
  eventTypes: string[];
  // false when the EventLogFile query threw. Lets consumers tell "Event Monitoring
  // off / no permission" (blind) apart from "accessible but genuinely no files".
  accessible?: boolean;
  // Populated only when accessible === false.
  accessError?: EventLogAccess;
}

// MfaRegistration: one entry per user with at least one registered MFA method.
// Populated by MfaRegistrationCheck, consumed by MfaMethodStrengthCheck.
export interface MfaRegistration {
  userId: string;
  username: string;
  profileName: string;
  methods: string[];
}

// EffectivePermissionGrant: per active user, the subset of catalogued high-risk
// permissions (see src/checks/permCatalog.ts) they hold *effectively* — i.e. via
// profile, assigned permission sets, OR permission set groups. Salesforce aggregates
// all of these into the user's PermissionSetAssignment rows (the PSG rows already
// reflect union-minus-muting), so a single PSA query yields the effective grant.
// Populated by PrivilegedAccessCheck, consumed by SeparationOfDutiesCheck.
export interface EffectivePermissionGrant {
  userId: string;
  username: string;
  name: string;
  profileName: string;
  /** Stable permission keys from DANGEROUS_PERMS held by this user. */
  perms: string[];
}

// AuditCache is mutable shared state passed through AuditContext.
// Keys are typed — rename any field and every check referencing it gets a compile error.
export interface AuditCache {
  healthCheckRisks?: HealthCheckRisk[];
  apexBodies?: ApexClassBody[];
  namedCredentialEndpoints?: string[];
  remoteSiteUrls?: string[];
  healthCloudInstalled?: boolean;
  // Populated by ConnectedAppsCheck — consumed by DeploymentIdentityCheck + SiemIntegrationCheck
  connectedAppNames?: string[];
  // Populated by ScheduledApexCheck — consumed by ApexLoggingCheck + SiemIntegrationCheck
  scheduledApexClassNames?: string[];
  // Populated by EventMonitoringCheck — consumed by SiemIntegrationCheck
  eventLogSummary?: EventLogSummary;
  // Populated by MfaRegistrationCheck — consumed by MfaMethodStrengthCheck
  mfaRegistrations?: MfaRegistration[];
  // Populated by VisualforceXssCheck — available for future VF-scanning checks
  vfPageBodies?: VfPageBody[];
  // Populated by PrivilegedAccessCheck — consumed by SeparationOfDutiesCheck
  effectivePermissions?: EffectivePermissionGrant[];
}
