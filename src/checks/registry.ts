import type { SecurityCheck } from './SecurityCheck.js';
import { HealthCheckCheck } from './impl/HealthCheckCheck.js';
import { UsersAndAdminsCheck } from './impl/UsersAndAdminsCheck.js';
import { PermissionsCheck } from './impl/PermissionsCheck.js';
import { LoginSessionCheck } from './impl/LoginSessionCheck.js';
import { ConnectedAppsCheck } from './impl/ConnectedAppsCheck.js';
import { SharingModelCheck } from './impl/SharingModelCheck.js';
import { ApiLimitsCheck } from './impl/ApiLimitsCheck.js';
import { AuditTrailCheck } from './impl/AuditTrailCheck.js';
import { InactiveUsersCheck } from './impl/InactiveUsersCheck.js';
import { PasswordSessionPolicyCheck } from './impl/PasswordSessionPolicyCheck.js';
import { IpRestrictionsCheck } from './impl/IpRestrictionsCheck.js';
import { GuestUserAccessCheck } from './impl/GuestUserAccessCheck.js';
import { RemoteSitesCheck } from './impl/RemoteSitesCheck.js';
import { NamedCredentialsCheck } from './impl/NamedCredentialsCheck.js';
import { HardcodedCredentialsCheck } from './impl/HardcodedCredentialsCheck.js';
import { ApexSharingCheck } from './impl/ApexSharingCheck.js';
import { FlowsWithoutSharingCheck } from './impl/FlowsWithoutSharingCheck.js';
import { PublicGroupSharingCheck } from './impl/PublicGroupSharingCheck.js';
import { FieldLevelSecurityCheck } from './impl/FieldLevelSecurityCheck.js';
import { ScheduledApexCheck } from './impl/ScheduledApexCheck.js';
import { CodeSecurityCheck } from './impl/CodeSecurityCheck.js';
import { CustomSettingsCheck } from './impl/CustomSettingsCheck.js';

// Order matters: a check's dependsOnCache must be satisfied by a preceding check's populatesCache.
// CheckEngine.validateCacheOrdering() enforces this at startup.
export const CHECKS: SecurityCheck[] = [
  new HealthCheckCheck(),          // writes: healthCheckRisks, healthCloudInstalled
  new UsersAndAdminsCheck(),       // writes: metrics (totalActiveUsers, etc.)
  new PermissionsCheck(),          // writes: metrics (permissionSetCount, profileCount)
  new LoginSessionCheck(),         // writes: metrics (failedLogins30d)
  new ConnectedAppsCheck(),        // writes: metrics (connectedAppsCount)
  new SharingModelCheck(),         // no deps, no cache
  new ApiLimitsCheck(),            // no deps, no cache
  new AuditTrailCheck(),           // no deps, no cache
  new InactiveUsersCheck(),        // writes: metrics (inactiveUsers90d)
  new PasswordSessionPolicyCheck(), // reads: healthCheckRisks (from HealthCheckCheck)
  new IpRestrictionsCheck(),       // no cache deps
  new GuestUserAccessCheck(),      // reads: healthCloudInstalled
  new RemoteSitesCheck(),          // writes: remoteSiteUrls
  new NamedCredentialsCheck(),     // writes: namedCredentialEndpoints
  new HardcodedCredentialsCheck(), // reads: namedCredentialEndpoints, remoteSiteUrls; writes: apexBodies
  new ApexSharingCheck(),          // reads: apexBodies
  new FlowsWithoutSharingCheck(),  // no deps
  new PublicGroupSharingCheck(),   // reads: healthCloudInstalled
  new FieldLevelSecurityCheck(),   // no deps
  new ScheduledApexCheck(),        // no deps
  new CodeSecurityCheck(),         // writes: metrics (apexClassCount, etc.)
  new CustomSettingsCheck(),       // no deps
];
