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
import { CspTrustedSitesCheck } from './impl/CspTrustedSitesCheck.js';
import { NamedCredentialsCheck } from './impl/NamedCredentialsCheck.js';
import { HardcodedCredentialsCheck } from './impl/HardcodedCredentialsCheck.js';
import { ApexSharingCheck } from './impl/ApexSharingCheck.js';
import { FlowsWithoutSharingCheck } from './impl/FlowsWithoutSharingCheck.js';
import { PublicGroupSharingCheck } from './impl/PublicGroupSharingCheck.js';
import { FieldLevelSecurityCheck } from './impl/FieldLevelSecurityCheck.js';
import { ScheduledApexCheck } from './impl/ScheduledApexCheck.js';
import { CodeSecurityCheck } from './impl/CodeSecurityCheck.js';
import { CustomSettingsCheck } from './impl/CustomSettingsCheck.js';
// Net-new SBS checks
import { StandardProfilesCheck } from './impl/StandardProfilesCheck.js';
import { SsoEnforcementCheck } from './impl/SsoEnforcementCheck.js';
import { MfaEnforcementCheck } from './impl/MfaEnforcementCheck.js';
import { ApiClientPermissionCheck } from './impl/ApiClientPermissionCheck.js';
import { IntegrationUsersCheck } from './impl/IntegrationUsersCheck.js';
import { ContentLinksCheck } from './impl/ContentLinksCheck.js';
import { FieldHistoryTrackingCheck } from './impl/FieldHistoryTrackingCheck.js';
import { DataClassificationCheck } from './impl/DataClassificationCheck.js';
import { DeploymentIdentityCheck } from './impl/DeploymentIdentityCheck.js';
import { ApexLoggingCheck } from './impl/ApexLoggingCheck.js';
import { EventMonitoringCheck } from './impl/EventMonitoringCheck.js';
import { SiemIntegrationCheck } from './impl/SiemIntegrationCheck.js';
// Additional security checks + recent Salesforce security improvements
import { ApexCrudFLSCheck } from './impl/ApexCrudFLSCheck.js';
import { ApexRestEndpointCheck } from './impl/ApexRestEndpointCheck.js';
import { VisualforceXssCheck } from './impl/VisualforceXssCheck.js';
import { CertificateExpiryCheck } from './impl/CertificateExpiryCheck.js';
import { InstalledPackagesCheck } from './impl/InstalledPackagesCheck.js';
import { TrustedIPRangesCheck } from './impl/TrustedIPRangesCheck.js';
import { AnonymousApexAuditCheck } from './impl/AnonymousApexAuditCheck.js';
import { DebugLogAccessCheck } from './impl/DebugLogAccessCheck.js';
import { ConnectedAppInactivityCheck } from './impl/ConnectedAppInactivityCheck.js';
import { MyDomainLoginPolicyCheck } from './impl/MyDomainLoginPolicyCheck.js';
import { InternalUserMfaCheck } from './impl/InternalUserMfaCheck.js';
import { MfaRegistrationCheck } from './impl/MfaRegistrationCheck.js';
import { MfaMethodStrengthCheck } from './impl/MfaMethodStrengthCheck.js';
import { HighAssuranceSessionCheck } from './impl/HighAssuranceSessionCheck.js';
import { EnhancedDomainsCheck } from './impl/EnhancedDomainsCheck.js';
import { ReleaseUpdatesCheck } from './impl/ReleaseUpdatesCheck.js';
import { LegacyApiVersionCheck } from './impl/LegacyApiVersionCheck.js';
import { ConnectedAppScopeCheck } from './impl/ConnectedAppScopeCheck.js';
import { TransactionSecurityPolicyCheck } from './impl/TransactionSecurityPolicyCheck.js';
import { FailedLoginCheck } from './impl/FailedLoginCheck.js';
import { ExperienceCloudSiteCheck } from './impl/ExperienceCloudSiteCheck.js';
import { CustomLabelsCredentialCheck } from './impl/CustomLabelsCredentialCheck.js';
import { ReportFolderAccessCheck } from './impl/ReportFolderAccessCheck.js';
// Attack-chain ingredient checks
import { EscalationPermsCheck } from './impl/EscalationPermsCheck.js';
import { CorsAllowlistCheck } from './impl/CorsAllowlistCheck.js';
import { GuestExecutableApexCheck } from './impl/GuestExecutableApexCheck.js';

// Order matters: a check's dependsOnCache must be satisfied by a preceding check's populatesCache.
// CheckEngine.validateCacheOrdering() enforces this at startup.
export const CHECKS: SecurityCheck[] = [
  new HealthCheckCheck(),          // writes: healthCheckRisks, healthCloudInstalled
  new UsersAndAdminsCheck(),       // no cache deps
  new PermissionsCheck(),          // no cache deps
  new LoginSessionCheck(),         // no cache deps
  new ConnectedAppsCheck(),        // writes: connectedAppNames
  new SharingModelCheck(),         // no deps
  new ApiLimitsCheck(),            // no deps
  new AuditTrailCheck(),           // no deps
  new InactiveUsersCheck(),        // no deps
  new PasswordSessionPolicyCheck(), // reads: healthCheckRisks
  new IpRestrictionsCheck(),       // no deps
  new GuestUserAccessCheck(),      // reads: healthCloudInstalled
  new RemoteSitesCheck(),          // writes: remoteSiteUrls
  new CspTrustedSitesCheck(),      // no deps
  new NamedCredentialsCheck(),     // writes: namedCredentialEndpoints
  new HardcodedCredentialsCheck(), // reads: namedCredentialEndpoints, remoteSiteUrls; writes: apexBodies
  new ApexSharingCheck(),          // reads: apexBodies
  new FlowsWithoutSharingCheck(),  // no deps
  new PublicGroupSharingCheck(),   // reads: healthCloudInstalled
  new FieldLevelSecurityCheck(),   // no deps
  new ScheduledApexCheck(),        // writes: scheduledApexClassNames
  new CodeSecurityCheck(),         // reads: apexBodies
  new CustomSettingsCheck(),       // no deps
  // SBS gap checks — no cache deps
  new StandardProfilesCheck(),     // SBS-ACS-005
  new SsoEnforcementCheck(),       // SBS-AUTH-001/002
  new MfaEnforcementCheck(),       // SBS-AUTH-004 (portal users)
  new ApiClientPermissionCheck(),  // SBS-ACS-006
  new IntegrationUsersCheck(),     // SBS-ACS-007/008/009
  new ContentLinksCheck(),         // SBS-FILE-001/002/003
  new FieldHistoryTrackingCheck(), // SBS-DATA-004
  new DataClassificationCheck(),   // SBS-DATA-001/002/003
  // Additional security checks — no cache deps
  new CertificateExpiryCheck(),    // cert store expiry
  new InstalledPackagesCheck(),    // managed/unmanaged package inventory
  new TrustedIPRangesCheck(),      // MFA-bypass IP ranges
  new AnonymousApexAuditCheck(),   // anonymous Apex in production
  new DebugLogAccessCheck(),       // active debug traces
  new MyDomainLoginPolicyCheck(),  // My Domain + AuthConfig SSO enforcement
  new HighAssuranceSessionCheck(), // connected app session timeout policies
  new EnhancedDomainsCheck(),      // Enhanced Domains URL isolation
  new InternalUserMfaCheck(),      // MFA for all internal standard users
  new ReleaseUpdatesCheck(),              // pending Salesforce release updates
  new LegacyApiVersionCheck(),            // old Apex API versions + SOAP remote sites
  new ConnectedAppScopeCheck(),           // OAuth scopes + refresh token policy
  new TransactionSecurityPolicyCheck(),   // automated threat detection policies
  new FailedLoginCheck(),                 // brute-force / credential stuffing detection
  new ExperienceCloudSiteCheck(),         // self-registration + guest access on live sites
  new CustomLabelsCredentialCheck(),      // credentials stored in globally-readable labels
  new ReportFolderAccessCheck(),          // public report folders — mass data exfiltration risk
  new EscalationPermsCheck(),             // priv-esc permission cluster (chain ingredient)
  new CorsAllowlistCheck(),               // wildcard/broad CORS origins (chain ingredient)
  // Cache-dependent checks — must come after their producers
  new DeploymentIdentityCheck(),   // reads connectedAppNames
  new ApexLoggingCheck(),          // reads apexBodies + scheduledApexClassNames
  new ConnectedAppInactivityCheck(), // reads connectedAppNames
  new ApexCrudFLSCheck(),          // reads apexBodies
  new GuestExecutableApexCheck(),  // reads apexBodies — guest-reachable Apex sharing
  new ApexRestEndpointCheck(),     // reads apexBodies
  new VisualforceXssCheck(),       // writes vfPageBodies
  new EventMonitoringCheck(),      // writes eventLogSummary
  new MfaRegistrationCheck(),      // writes mfaRegistrations
  new SiemIntegrationCheck(),      // reads namedCredentialEndpoints, remoteSiteUrls,
                                   //   connectedAppNames, scheduledApexClassNames, eventLogSummary
  new MfaMethodStrengthCheck(),    // reads mfaRegistrations
];
