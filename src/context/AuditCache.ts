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

// Why the Agentforce/GenAI Tooling queries returned nothing. Mirrors EventLogAccess:
//   'not-enabled' : the GenAI/Bot objects do not exist in this org (Agentforce is not
//                   provisioned) — BotDefinition/GenAiPlannerDefinition raise
//                   INVALID_TYPE / "sObject type not supported". The org has no agents.
//   'unknown'     : the queries failed for a reason we could not attribute (e.g. a
//                   partial failure or a permission gap). Consumers stay silent rather
//                   than assert an inventory they could not fully build.
// 'ok' is set only when the agent queries succeeded (even if zero agents were found).
export type AgentAccess = 'ok' | 'not-enabled' | 'unknown';

// AgentDefinition: one Agentforce agent or classic Einstein Bot. Populated by
// AgentInventoryCheck from Tooling BotDefinition + BotVersion (+ GenAiPlannerDefinition),
// consumed by the AI & Agents dependent checks (agent-user-privilege, agent-channel-exposure,
// agent-action-surface, agent-monitoring-coverage).
export interface AgentDefinition {
  developerName: string;
  label: string;
  // 'agent' = Agentforce/GenAI agent; 'classic-bot' = legacy Einstein Bot.
  type: 'agent' | 'classic-bot';
  isActive: boolean;
  // Active BotVersion number, when a version is active.
  activeVersion?: number;
  // The user the agent executes as, when resolvable from the definition.
  runAsUserId?: string;
  // False when the run-as user is inactive or frozen; undefined when not resolved.
  runAsUserActive?: boolean;
}

// AgentUser: a user on the "Einstein Agent User" profile or holding an Agentforce /
// Einstein Agent permission set license. Populated by AgentInventoryCheck, consumed by
// agent-user-privilege. permissionSetIds / permissionSetLicenseNames come from the
// PermissionSetAssignment / PermissionSetLicenseAssign joins.
export interface AgentUser {
  userId: string;
  username: string;
  profileName: string;
  isActive: boolean;
  permissionSetIds: string[];
  permissionSetLicenseNames: string[];
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
  // Populated by AgentInventoryCheck — consumed by the AI & Agents dependent checks
  agentInventory?: AgentDefinition[];
  agentUsers?: AgentUser[];
  // Why the agent queries returned nothing (mirrors eventLogSummary.accessError semantics).
  agentAccess?: AgentAccess;
}
