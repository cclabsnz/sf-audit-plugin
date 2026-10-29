# Feature inventory

This file lists what sf-audit already does and where each piece lives. Search here before
building a check, chain, helper or report section. If something close exists, extend it instead
of writing a second one. `test/unit/featureInventory.test.ts` fails when a check id, a named chain
id or a command under `src/commands` is missing from this file, so add the line in the same change
that adds the feature.

Longer write-ups: [CHECKS.md](CHECKS.md), [ATTACK-CHAINS.md](ATTACK-CHAINS.md),
[COMMANDS.md](COMMANDS.md), [ARCHITECTURE.md](ARCHITECTURE.md), [COMPLIANCE.md](COMPLIANCE.md),
[SCORING.md](SCORING.md).

## Commands

Each is an oclif command under `src/commands`; the id is the path with spaces.

| Command | What it does | Flags worth knowing | File |
|---|---|---|---|
| `audit security` | Runs every check, correlates chains, grades A-F, writes reports | `--format html,md,json,executive,sarif`, `--checks`, `--fail-on`, `--fail-on-inconclusive`, `--waivers`, `--scoring-config`, `--digest`, `--frameworks`, `--top`, `--prepared-for`, `--branding`, `--resolve-domains`, `--no-history` | src/commands/audit/security.ts |
| `audit list` | Lists every registered check with id and description | none | src/commands/audit/list.ts |
| `audit preflight` | Reports what the audit user can and cannot establish (missing permissions per check) | `--target-org` | src/commands/audit/preflight.ts |
| `audit diff` | Compares two audit JSON reports | `--format html,json`, `--output` | src/commands/audit/diff.ts |
| `audit history` | HTML timeline of archived runs for an org | `--output`, `--limit` | src/commands/audit/history.ts |
| `audit events pull` | Captures free EventLogFile daily logs to local disk | `--since`, `--types`, `--output` | src/commands/audit/events/pull.ts |
| `audit apps` | Connected-app least privilege from API log usage; can emit permission sets | `--since`, `--from`, `--soak`, `--format table,json,md`, `--emit-permset` | src/commands/audit/apps.ts |
| `audit timeline` | Rebuilds one actor's activity across captured event types, offline | `--org-id`, `--input`, `--window`, `--seed`, `--allow-shared-identity`, `--max-cardinality`, `--format csv,json,md` | src/commands/audit/timeline.ts |
| `audit incident collect` | Collects a guest-filtered evidence bundle for a Guest User Anomaly investigation | `--since`, `--window`, `--event`, `--ip-ranges`, `--output` | src/commands/audit/incident/collect.ts |
| `audit incident report` | Analyses an incident bundle offline and writes the report | `--bundle`, `--format html,md,json`, `--redact`, `--spike-ratio`, `--branding`, `--prepared-for` | src/commands/audit/incident/report.ts |

Supporting code per command: `src/apps/` (audit apps), `src/timeline/` (audit timeline),
`src/incident/` (incident collect and report), `src/history/` (history, diff, run archive),
`src/preflight/` (preflight).

## Security checks

All 109 checks are registered, in run order, in `CHECKS` in src/checks/registry.ts. Order matters:
a check that reads a cache key must run after the check that writes it (`CheckEngine` enforces
this). Grouped by each check's declared `category`. Interface: src/checks/SecurityCheck.ts.

### AI & Agents

| Check id | Name | Purpose | File |
|---|---|---|---|
| `genai-prompt-template-grounding` | GenAI Prompt Template Grounding & Context | Inspects active GenAI Prompt Templates for grounding on System-Mode Flows or without-sharing Apex, and untrusted CRM input interpolation | src/checks/impl/GenAiPromptTemplateGroundingCheck.ts |
| `agent-inventory` | Agentforce Agent Inventory | Inventories Agentforce agents and classic Einstein Bots, their active versions, run-as users, and the users licensed to run agents | src/checks/impl/AgentInventoryCheck.ts |
| `agent-user-privilege` | Agent User Privilege | Flags Agentforce run-as / agent users whose effective access is over-broad: Modify/View All Data, write access to many objects, or read... | src/checks/impl/AgentUserPrivilegeCheck.ts |
| `agent-action-surface` | Agent Action Surface | Inventories Agentforce topics and actions (GenAiPlugin / GenAiFunction), flagging write-capable actions (Apex/Flow that create, update... | src/checks/impl/AgentActionSurfaceCheck.ts |
| `agent-channel-exposure` | Agentforce Channel Exposure | Correlates active Agentforce agents with the channels that reach them (Experience Cloud sites, embedded deployments, messaging channels)... | src/checks/impl/AgentChannelExposureCheck.ts |
| `agent-monitoring-coverage` | Agentforce Monitoring Coverage | Flags orgs that run active Agentforce agents without Event Monitoring capture or Transaction Security policies to detect and respond to... | src/checks/impl/AgentMonitoringCoverageCheck.ts |
| `agent-query-reach` | Agent Query Reach | Flags agents that carry the standard General CRM topic or a Query Records action, which lets an injected prompt query any object the... | src/checks/impl/AgentQueryReachCheck.ts |
| `agent-outbound-actions` | Agent Outbound Actions | Flags agent actions that send data out of the org (Slack messages, email, external services and MCP tools, including Flow actions whose... | src/checks/impl/AgentOutboundActionsCheck.ts |
| `trusted-url-hygiene` | Trusted URL Hygiene | Reviews the CSP trusted-sites allowlist for non-Salesforce domains that could be repurposed as data-exfiltration channels (the... | src/checks/impl/TrustedUrlHygieneCheck.ts |

### Access Control

| Check id | Name | Purpose | File |
|---|---|---|---|
| `guest-user-access` | Guest User Access | Audits object permissions and sharing rules granted to unauthenticated guest users | src/checks/impl/GuestUserAccessCheck.ts |
| `experience-cloud-site` | Experience Cloud Site Security | Checks live Experience Cloud sites for self-registration enabled (attacker account creation) and guest user presence | src/checks/impl/ExperienceCloudSiteCheck.ts |
| `guest-object-exposure` | Guest Object Exposure (Bulk Read via UI API) | Auto-discovers every object an unauthenticated guest can read in bulk via the UI API (GraphQL), including records exposed by guest... | src/checks/impl/GuestObjectExposureCheck.ts |
| `guest-site-options` | Experience Cloud Guest Site Options | Checks Experience Cloud sites for guest file access and guest member visibility, which expose files and member identities to... | src/checks/impl/GuestSiteOptionsCheck.ts |
| `guest-record-access-policy` | Secure Guest User Record Access | Verifies the "Secure guest user record access" enforcement is activated, the guardrail that stops guest-owned records defeating a... | src/checks/impl/GuestRecordAccessPolicyCheck.ts |
| `login-access-policy` | Login-As & Delegated Administration | Flags delegated-administration groups and the org login-as policy, which allow user impersonation and scoped admin escalation that... | src/checks/impl/LoginAccessPolicyCheck.ts |
| `classic-sites` | Classic Force.com Sites | Flags active classic (Visualforce) Force.com Sites and their guest users | src/checks/impl/ClassicSitesCheck.ts |
| `guest-api-access` | Guest API & Bulk Access | Flags guest users granted API Enabled or Bulk API Hard Delete | src/checks/impl/GuestApiAccessCheck.ts |
| `guest-user-visibility` | Guest Visibility of Other Users | Checks whether unauthenticated guests can see other User records through View All Users, and whether a public external OWD on User shows the roster to logged-in external users | src/checks/impl/GuestUserVisibilityCheck.ts |
| `experience-csp` | Experience Cloud CSP & Lightning Web Security | Advises verifying Strict CSP and Lightning Web Security on live Experience Cloud sites (not reliably API-readable), to limit... | src/checks/impl/ExperienceCspCheck.ts |
| `guest-executable-apex` | Guest-Executable Apex | Finds Apex classes that unauthenticated guest profiles can execute, flagging those that run without sharing, call a without-sharing... | src/checks/impl/GuestExecutableApexCheck.ts |

### App Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `connected-apps` | Connected Apps | Flags connected apps not restricted to admin-approved users | src/checks/impl/ConnectedAppsCheck.ts |
| `installed-packages` | Installed Packages | Inventories installed managed and unmanaged packages; flags unmanaged packages and beta releases in production | src/checks/impl/InstalledPackagesCheck.ts |
| `connected-app-scope` | Connected App OAuth Scopes & Token Policy | Flags connected apps granting Full OAuth scope or using infinite refresh token policies | src/checks/impl/ConnectedAppScopeCheck.ts |
| `connected-app-inactivity` | Inactive Connected Apps | Flags connected apps with no OAuth logins in the past 90 days | src/checks/impl/ConnectedAppInactivityCheck.ts |
| `oauth-token-inventory` | Standing OAuth Token Inventory | Inventories live OAuth tokens per app | src/checks/impl/OauthTokenInventoryCheck.ts |

### Authentication

| Check id | Name | Purpose | File |
|---|---|---|---|
| `sso-enforcement` | SSO Enforcement | Detects username-password logins indicating SSO is not org-wide enforced | src/checks/impl/SsoEnforcementCheck.ts |
| `mfa-enforcement` | MFA for External Users | Checks that external/portal users with data access have MFA enforced | src/checks/impl/MfaEnforcementCheck.ts |
| `certificate-expiry` | Certificate Expiry | Checks installed certificates for impending expiry (30 / 90 / 180 day thresholds) | src/checks/impl/CertificateExpiryCheck.ts |
| `trusted-ip-ranges` | Trusted IP Ranges | Identifies trusted IP ranges that completely bypass MFA, including overly broad ranges | src/checks/impl/TrustedIPRangesCheck.ts |
| `my-domain-login-policy` | My Domain Login Policy | Checks that My Domain is configured and login from login.salesforce.com is prevented | src/checks/impl/MyDomainLoginPolicyCheck.ts |
| `high-assurance-session` | High Assurance Session Requirements | Checks whether connected apps with admin-like capabilities require short session timeouts or high-assurance MFA sessions | src/checks/impl/HighAssuranceSessionCheck.ts |
| `enhanced-domains` | Enhanced Domains | Verifies Enhanced Domains is enabled | src/checks/impl/EnhancedDomainsCheck.ts |
| `internal-user-mfa` | Internal User MFA Enforcement | Checks MFA enforcement for all active internal standard users | src/checks/impl/InternalUserMfaCheck.ts |
| `auth-providers` | Auth Providers & External IdPs | Reviews configured Auth Providers and SAML SSO configurations | src/checks/impl/AuthProvidersCheck.ts |
| `mfa-registration` | MFA Method Registration | Identifies active standard users with no MFA method (authenticator app, Salesforce Authenticator, security key, built-in authenticator) in TwoFactorMethodsInfo; needs "Manage MFA in API" | src/checks/impl/MfaRegistrationCheck.ts |
| `mfa-method-strength` | MFA Method Strength | Classifies registered MFA methods by strength (phishing-resistant / TOTP / weak) using Salesforce's guidance and NIST; flags admin users... | src/checks/impl/MfaMethodStrengthCheck.ts |

### Code Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `hardcoded-credentials` | Hardcoded Credentials | Scans Apex code for hardcoded Bearer tokens, Basic auth, API keys, and raw callout URLs | src/checks/impl/HardcodedCredentialsCheck.ts |
| `apex-sharing` | Apex Sharing Declarations | Classifies Apex classes by sharing declaration (with sharing, without sharing, inherited, omitted) | src/checks/impl/ApexSharingCheck.ts |
| `scheduled-apex` | Scheduled and Batch Apex | Lists active scheduled and batch Apex jobs running in the org | src/checks/impl/ScheduledApexCheck.ts |
| `code-security` | Code Security and Coverage | Reports org-wide Apex test coverage, class/trigger counts, and flags potential SOQL injection patterns | src/checks/impl/CodeSecurityCheck.ts |
| `custom-settings` | Custom Settings and Credentials | Flags custom settings with credential-like names that may store secrets | src/checks/impl/CustomSettingsCheck.ts |
| `anonymous-apex-audit` | Anonymous Apex Execution Audit | Detects anonymous Apex execution in the last 90 days via SetupAuditTrail | src/checks/impl/AnonymousApexAuditCheck.ts |
| `platform-event-subscriber-context` | Platform Event Subscriber Context & Privilege Escalation | Detects Platform Event subscribers executing in system context or as Admin while low-trust or guest users hold Publish permissions | src/checks/impl/PlatformEventSubscriberContextCheck.ts |
| `apex-logging` | Apex Logging Framework | Checks for persistent logging framework usage and sensitive data in Apex logs | src/checks/impl/ApexLoggingCheck.ts |
| `apex-crud-fls` | Apex CRUD/FLS Enforcement | Flags Apex classes that perform DML or SOQL without checking CRUD/FLS permissions: OWASP Top 10 for Salesforce | src/checks/impl/ApexCrudFLSCheck.ts |
| `apex-rest-endpoint` | Apex REST Endpoint Security | Flags @RestResource Apex classes that run without sharing, exposing records to REST callers without record-level access control | src/checks/impl/ApexRestEndpointCheck.ts |
| `visualforce-xss` | Visualforce XSS Patterns | Scans Visualforce page markup for common XSS patterns | src/checks/impl/VisualforceXssCheck.ts |
| `lightning-message-channel` | Lightning Message Channel Exposure | Finds Lightning Message Channels published to every namespace, where any component sharing the page can read or write the bus | src/checks/impl/LightningMessageChannelCheck.ts |

### Data Access

| Check id | Name | Purpose | File |
|---|---|---|---|
| `field-level-security` | Field-Level Security | Detects sensitive custom fields (SSN, credit card, tax ID) exposed to broad permission sets | src/checks/impl/FieldLevelSecurityCheck.ts |

### Data Access Control

| Check id | Name | Purpose | File |
|---|---|---|---|
| `sharing-model` | Org-Wide Defaults (OWD) Sharing Model | Checks OWD sharing settings for Account, Contact, Opportunity, Case, and Lead, covering both internal and external (portal) sharing models | src/checks/impl/SharingModelCheck.ts |
| `report-folder-access` | Report Folder Public Access | Checks for Report folders with Public access | src/checks/impl/ReportFolderAccessCheck.ts |
| `data-export-access` | Mass Data Export Access | Flags profiles/permission sets granting Weekly Data Export or API access combined with View/Modify All Data | src/checks/impl/DataExportAccessCheck.ts |

### Data Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `field-history-tracking` | Field History Tracking | Verifies field history tracking is enabled on sensitive standard objects | src/checks/impl/FieldHistoryTrackingCheck.ts |
| `data-classification` | Data Classification and Encryption | Checks Salesforce field data classification usage and Shield Platform Encryption | src/checks/impl/DataClassificationCheck.ts |
| `encryption-coverage` | Encryption Coverage for Sensitive Fields | Flags fields classified as sensitive (PII/PHI via ComplianceGroup) that are not encrypted at rest with Shield Platform Encryption | src/checks/impl/EncryptionCoverageCheck.ts |
| `sandbox-data-masking` | Sandbox Data Masking | In sandboxes, flags the presence of populated PII fields (likely unmasked production data) and advises running Salesforce Data Mask | src/checks/impl/SandboxDataMaskingCheck.ts |
| `data-cloud-data-space-isolation` | Data Cloud Data Space Isolation | Flags orgs where external integrations, partner users, or agent users are mapped to the default Data Space, or unconstrained Data Share... | src/checks/impl/DataCloudDataSpaceIsolationCheck.ts |
| `restriction-rules-integrity` | Restriction Rules Integrity & Conflict Detection | Detects inactive or conflicting Restriction Rules on sensitive standard and custom objects | src/checks/impl/RestrictionRulesIntegrityCheck.ts |
| `shield-tenant-secret-lifecycle` | Shield Platform Encryption Tenant Secret Lifecycle | Monitors Shield TenantSecret rotation frequency (>365 days) and destroyed key status for cryptographic compliance | src/checks/impl/ShieldTenantSecretLifecycleCheck.ts |

### Deployments

| Check id | Name | Purpose | File |
|---|---|---|---|
| `deployment-identity` | Deployment Identity | Checks for a designated deployment identity and monitors for uncontrolled deployment activity | src/checks/impl/DeploymentIdentityCheck.ts |

### Event Monitoring

| Check id | Name | Purpose | File |
|---|---|---|---|
| `event-monitoring` | Event Monitoring Storage | Verifies Event Monitoring is enabled and logs cover at least 30 days | src/checks/impl/EventMonitoringCheck.ts |
| `siem-integration` | SIEM Integration Signals | Detects evidence of SIEM or external monitoring integration using cached org data (zero extra queries) | src/checks/impl/SiemIntegrationCheck.ts |

### External Connectivity

| Check id | Name | Purpose | File |
|---|---|---|---|
| `remote-sites` | Remote Site Settings | Inventories remote site settings and flags those with protocol security disabled | src/checks/impl/RemoteSitesCheck.ts |
| `named-credentials` | Named Credentials | Inventories Named Credentials and flags any not referenced in Apex code | src/checks/impl/NamedCredentialsCheck.ts |
| `cors-allowlist` | CORS Allowlist | Flags wildcard or overly broad CORS allowlist origins | src/checks/impl/CorsAllowlistCheck.ts |
| `email-security` | Email Security & Spoofing | Flags inbound email services that accept mail from any sender or run Apex without authentication | src/checks/impl/EmailSecurityCheck.ts |
| `outbound-messages` | Workflow Outbound Messages | Flags workflow outbound messages that include a Salesforce session ID or post to cleartext (http://) endpoints | src/checks/impl/OutboundMessagesCheck.ts |
| `external-credentials` | External Credential Authentication | Grades External Credential authentication protocols, flagging callouts that use no authentication or a custom (non-standard) scheme | src/checks/impl/ExternalCredentialsCheck.ts |
| `inbound-email-handler-exposure` | Inbound Email Handler Unauthenticated Execution | Detects active inbound email services open to all senders without SPF/DKIM verification executing Apex under privileged users | src/checks/impl/InboundEmailHandlerExposureCheck.ts |
| `org-wide-email-spoofing` | Org-Wide Email Spoofing & DKIM Coverage | Flags org-wide email addresses open to all profiles and missing DKIM keys enabling internal and outbound email spoofing | src/checks/impl/OrgWideEmailSpoofingCheck.ts |

### External-Facing Access

| Check id | Name | Purpose | File |
|---|---|---|---|
| `external-account-hierarchy-exposure` | External Account Hierarchy & Partner Super User Exposure | Flags Partner Super User access and External Account Hierarchies that bypass external OWD and widen portal visibility | src/checks/impl/ExternalAccountHierarchyExposureCheck.ts |

### File Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `content-links` | Content Distribution Links | Audits public content links for missing expiry, missing passwords, and stale records | src/checks/impl/ContentLinksCheck.ts |
| `public-content-exposure` | Public Static Resources & Documents | Flags Documents marked externally available (retrievable without authentication) and static resources cached publicly | src/checks/impl/PublicContentExposureCheck.ts |

### Flow Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `flows-without-sharing` | Flows Without Sharing Context | Identifies active autolaunched and screen flows set to run in system context without sharing | src/checks/impl/FlowsWithoutSharingCheck.ts |

### Health Check

| Check id | Name | Purpose | File |
|---|---|---|---|
| `health-check` | Security Health Check | Reads the Salesforce Health Check score and flags individual risk items | src/checks/impl/HealthCheckCheck.ts |

### Identity & Access

| Check id | Name | Purpose | File |
|---|---|---|---|
| `password-session-policy` | Password and Session Policy | Evaluates password complexity, session timeout, and MFA enforcement from Health Check data | src/checks/impl/PasswordSessionPolicyCheck.ts |
| `ip-restrictions` | Login IP Restrictions | Checks admin profiles for missing IP range restrictions and connected apps with relaxed IP policies | src/checks/impl/IpRestrictionsCheck.ts |
| `oauth-device-and-asset-token-flows` | OAuth Device & Password Flows | Flags OAuth 2.0 Device Flow and Username-Password Flow enabled in OAuth and OpenID Connect Settings | src/checks/impl/OauthDeviceAndAssetTokenFlowsCheck.ts |
| `delegated-authentication-exposure` | Delegated Authentication Exposure | Flags Delegated Authentication enabled over non-mTLS endpoints or assigned to System Administrator profiles | src/checks/impl/DelegatedAuthenticationExposureCheck.ts |
| `auth-provider-registration-handler` | Auth.Provider Registration Handler Security | Detects Auth.Provider RegistrationHandler running as Admin with email-based account linking vulnerable to pre-auth takeover | src/checks/impl/AuthProviderRegistrationHandlerCheck.ts |

### Integration Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `flow-http-callout-credential-bypass` | Flow HTTP Callout Credential Bypass | Detects declarative Flow HTTP callouts storing credentials in formulas or bypassing modern Named Credentials | src/checks/impl/FlowHttpCalloutCredentialBypassCheck.ts |

### Monitoring

| Check id | Name | Purpose | File |
|---|---|---|---|
| `threat-detection` | Threat Detection Event Storage | Verifies Real-Time Event Monitoring Threat Detection storage (Guest User Anomaly and siblings) is enabled and retaining events to detect... | src/checks/impl/ThreatDetectionCheck.ts |

### Network Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `csp-trusted-sites` | CSP Trusted Sites | Checks Content Security Policy trusted sites for insecure HTTP endpoints that allow mixed-content loading | src/checks/impl/CspTrustedSitesCheck.ts |

### Permissions

| Check id | Name | Purpose | File |
|---|---|---|---|
| `permissions` | Permissions | Reports unassigned permission sets and high profile counts that increase the attack surface | src/checks/impl/PermissionsCheck.ts |
| `standard-profiles` | Standard Profile Usage | Flags active users assigned to out-of-the-box Salesforce standard profiles | src/checks/impl/StandardProfilesCheck.ts |
| `api-client-permission` | Use Any API Client Permission | Flags users with the "Use Any API Client" permission which bypasses API Access Control | src/checks/impl/ApiClientPermissionCheck.ts |
| `soap-login-api-auth` | SOAP login() Use Any API Auth Readiness | Flags SOAP login() users lacking "Use Any API Auth" (Winter '27), and holders that no longer need it | src/checks/impl/SoapLoginApiAuthCheck.ts |
| `integration-users` | Integration / Service Account Inventory | Inventories non-human identities and checks for excess privilege | src/checks/impl/IntegrationUsersCheck.ts |
| `integration-least-privilege` | Integration Account Least Privilege | Reports permissions held by integration and service accounts that the account is not using | src/checks/impl/IntegrationLeastPrivilegeCheck.ts |
| `escalation-perms` | Privilege Escalation Permissions | Flags users holding lateral-movement/persistence permissions (Manage Internal Users, Assign Permission Sets, Modify Metadata, Manage... | src/checks/impl/EscalationPermsCheck.ts |
| `privileged-access` | Privileged Access & Shadow Admins | Resolves effective high-risk permissions per user; flags admin-equivalents off the System Administrator profile | src/checks/impl/PrivilegedAccessCheck.ts |
| `separation-of-duties` | Separation of Duties | Flags users whose effective permissions combine into self-escalation, fraud, or undetectable-abuse pairings that violate separation of... | src/checks/impl/SeparationOfDutiesCheck.ts |

### Platform Hygiene

| Check id | Name | Purpose | File |
|---|---|---|---|
| `release-updates` | Pending Release Updates | Flags Salesforce release updates (Critical Updates) that are pending activation, especially those past their auto-activation date | src/checks/impl/ReleaseUpdatesCheck.ts |
| `legacy-api-version` | Legacy API Versions | Flags Apex classes compiled on old API versions and detects SOAP-based remote site integrations | src/checks/impl/LegacyApiVersionCheck.ts |
| `package-post-install-supply-chain` | Package Post-Install Supply Chain Risk | Finds packaged Apex implementing InstallHandler, which runs in system context on every install and push upgrade | src/checks/impl/PackagePostInstallSupplyChainCheck.ts |

### Privileged Access

| Check id | Name | Purpose | File |
|---|---|---|---|
| `delegated-administration-groups` | Delegated Administration Groups | Identifies unmonitored Delegated Admin Groups that grant shadow-admin privileges outside profiles and permission sets | src/checks/impl/DelegatedAdministrationGroupsCheck.ts |

### Resource Management

| Check id | Name | Purpose | File |
|---|---|---|---|
| `api-limits` | API and Resource Limits | Monitors API request consumption against daily and concurrent limits | src/checks/impl/ApiLimitsCheck.ts |

### Secrets Management

| Check id | Name | Purpose | File |
|---|---|---|---|
| `custom-labels-credential` | Custom Labels Credential Exposure | Scans Custom Labels for API keys, tokens, and credentials | src/checks/impl/CustomLabelsCredentialCheck.ts |

### Security Controls

| Check id | Name | Purpose | File |
|---|---|---|---|
| `audit-trail` | Audit Trail | Reviews setup audit trail for permission changes and Login-As events | src/checks/impl/AuditTrailCheck.ts |
| `debug-log-access` | Active Debug Log Traces | Identifies active TraceFlag records that capture debug logs, including high-detail traces that expose sensitive field values | src/checks/impl/DebugLogAccessCheck.ts |

### Session Security

| Check id | Name | Purpose | File |
|---|---|---|---|
| `login-session` | Login Session | Analyses login history for failed login trends, Login-As events, and access from diverse IPs | src/checks/impl/LoginSessionCheck.ts |
| `session-hardening` | Session & Clickjack Hardening | Grades clickjack, CSRF, session-lock, and XSS-protection settings from Health Check and gives per-setting remediation | src/checks/impl/SessionHardeningCheck.ts |

### Sharing & Visibility

| Check id | Name | Purpose | File |
|---|---|---|---|
| `public-group-sharing` | Public Group Sharing Exposure | Finds sharing rules that grant broad access to All Internal Users | src/checks/impl/PublicGroupSharingCheck.ts |

### Threat Detection

| Check id | Name | Purpose | File |
|---|---|---|---|
| `transaction-security-policy` | Transaction Security Policies | Checks whether Transaction Security Policies are configured to provide automated threat detection and response | src/checks/impl/TransactionSecurityPolicyCheck.ts |
| `failed-login-detection` | Failed Login Detection | Analyses LoginHistory to detect brute-force and credential stuffing patterns from the last 7 days | src/checks/impl/FailedLoginCheck.ts |
| `login-anomaly` | Anomalous Successful Logins | Flags user accounts with successful logins from an unusually high number of distinct source IPs (credential-sharing / account-compromise... | src/checks/impl/LoginAnomalyCheck.ts |
| `guest-traffic-anomaly` | Guest Traffic Anomaly | Scans recent EventLogFile guest requests for anonymizer/hosting source IPs, single-IP bursts, and GraphQL totalCount reconnaissance sweeps | src/checks/impl/GuestTrafficAnomalyCheck.ts |

### Users & Admins

| Check id | Name | Purpose | File |
|---|---|---|---|
| `users-and-admins` | Users and Admins | Identifies users with dangerous system-wide permissions (ModifyAllData, ViewAllData, AuthorApex, CustomizeApplication) | src/checks/impl/UsersAndAdminsCheck.ts |
| `inactive-users` | Inactive Users | Finds active licensed users with no login in the past 90 days | src/checks/impl/InactiveUsersCheck.ts |


## Attack chains

Correlation runs in `ChainEngine.correlate` (src/chains/ChainEngine.ts) in two passes.

- Named pass (`runNamedPass`): matches every `NAMED_CHAINS` entry below against the active findings. Only named chains reach CRITICAL.
- Emergent pass (`runEmergentPass`): builds `potential-<source>-<sink>` chains from any source capability (`SOURCE_CAPS`) to any high-impact sink (`HIGH_IMPACT_SINKS`) that a named chain does not already cover. Potential chains are capped at HIGH.

Named chains, all defined in src/chains/namedChains.ts (finding groups such as `GUEST_EXPOSURE` and `EGRESS_PATHS` are exported from the same file):

| Chain id | Title |
|---|---|
| `unauth-bulk-exfil` | Unauthenticated bulk exfiltration |
| `active-guest-exfil` | Active guest reconnaissance against an exposed data surface |
| `standard-to-takeover` | Standard user to org takeover |
| `cred-theft-pivot` | Credential theft to external pivot |
| `soql-injection-read` | SOQL injection to mass read |
| `prompt-injection-blast-radius` | Prompt injection blast radius |
| `forcedleak-pattern` | ForcedLeak pattern (agent exfiltration via a stale trusted URL) |
| `salesbleed-pattern` | SalesBleed pattern (agent with open-ended query reach plus an outbound path) |
| `sandbox-pii-exposure` | Unmasked production PII in a weakly-controlled sandbox |
| `insider-bulk-exfil` | Insider bulk export without monitoring |
| `undetected-compromise` | Exploitable access with no detection coverage |
| `mfa-bypass-admin` | MFA bypass to privileged compromise |
| `oauth-standing-access` | Standing OAuth access outside every login control |
| `self-registration-foothold` | Self-service registration into an over-shared portal |
| `session-id-egress` | Live session ID handed to an external endpoint |
| `anonymous-file-exposure` | Org files served to anonymous callers, with no record of what left |
| `xss-to-privileged-session` | Visualforce XSS pattern reaching a privileged session |
| `inbound-email-rce` | Unauthenticated inbound email to privileged code execution |
| `platform-event-priv-esc` | Guest or low-trust platform event publish to automated process escalation |

Chain building blocks:

- src/chains/Capability.ts: the `Capability` vocabulary, `ALL_CAPABILITIES`, `SOURCE_CAPS`, `HIGH_IMPACT_SINKS`.
- src/chains/CapabilityRegistry.ts: `CAPABILITY_REGISTRY` (finding id or prefix to granted/required capabilities) and `capabilitiesFor(finding)`. A new finding that should take part in chains gets an entry here.
- src/chains/AttackChain.ts: `AttackChain`, `AttackChainStep`, `AttackChainAbuseCase` shapes.
- src/chains/namedChains.ts: `NamedChainDef`, `FindingGroup`, `AbuseCaseDef`, `inGroup(finding, group)`.

## Reports and renderers

| Renderer | Output | File |
|---|---|---|
| `HtmlRenderer` | `--format html`: full technical report, embeds the attack-chain DAG | src/renderers/HtmlRenderer.ts |
| `MarkdownRenderer` | `--format md` | src/renderers/MarkdownRenderer.ts |
| `JsonRenderer` | `--format json` (input to `audit diff` and history) | src/renderers/JsonRenderer.ts |
| `SarifRenderer` | `--format sarif` for code-scanning upload; `riskToSarifLevel` | src/renderers/SarifRenderer.ts |
| `ClientReportRenderer` | `--format executive`: executive deck (priorities, attack journey, roadmap, compliance matrix, threat view, action plan) | src/renderers/ClientReportRenderer.ts |
| `renderAttackChainDagSvg` | Attack-chain DAG as inline SVG; `breakPointIndices` marks where a fix breaks the chain | src/renderers/AttackChainDagRenderer.ts |
| `DiffHtmlRenderer` | `audit diff` HTML | src/renderers/DiffHtmlRenderer.ts |
| `DiffJsonRenderer` | `audit diff` JSON | src/renderers/DiffJsonRenderer.ts |
| `HistoryRenderer` | `audit history` HTML timeline with Chart.js | src/renderers/HistoryRenderer.ts |
| `AuditRenderer`, `DiffRenderer` | Renderer interfaces | src/renderers/AuditRenderer.ts, src/renderers/DiffRenderer.ts |
| `chartJsScript` | Inlined Chart.js script for HTML outputs | src/renderers/chartAsset.ts |
| `deckFontFaceCss` | Embedded deck fonts | src/renderers/deckFonts.ts |
| `toolCreditHtml`, `toolCreditMarkdown`, `toolCreditUrl` | Tool credit line in reports | src/renderers/toolCredit.ts |
| apps renderers | `renderTable`, `renderJson`, `renderMarkdown` for `audit apps` | src/apps/renderApps.ts |
| timeline renderers | `renderCsv`, `renderJson`, `renderSummary` for `audit timeline` | src/timeline/render.ts |
| incident renderers | `renderHtml`, `renderMarkdown`, `buildEvidence`/`writeEvidence`, `redactResult` | src/incident/render/ |

Report section builders used by the executive deck (src/report):

- `buildActionPlan`: every action, ordered (src/report/ActionPlan.ts).
- `buildAttackJourney`: chain narrative for the deck (src/report/AttackJourney.ts).
- `buildComplianceMatrix`: per-framework control status (src/report/ComplianceMatrix.ts).
- `selectPriorities`: top-N executive priorities (src/report/ExecutivePriorities.ts).
- `buildRoadmap`: remediation roadmap (src/report/RemediationRoadmap.ts).

## Shared helpers (reuse, do not re-implement)

Check support, src/checks/support:

- src/checks/support/apexAccess.ts: `apexCode`, `codeWithoutStrings`, `classDeclarations`, `sharingKeyword`, `parentClass`, `effectiveSharing`, `omittedSharingEnforced` (+ `OMITTED_SHARING_ENFORCED_FROM`), `apexApiVersions`, `enteredOnlyThroughAura`, `usesSystemMode`, `declaresWithoutSharing`, constants `SYSTEM_MODE`, `DML_AS_SYSTEM`, `DML_AS_USER`. Use for any with/without sharing or SYSTEM_MODE reasoning.
- src/checks/support/guestShares.ts: `guestPrincipals` (guest users, guest user groups, and the public groups and queues they are in, nested), `guestShareWhere`, `shareTableOf`, `guestShareCount`, `guestReadsSample` (UserRecordAccess on up to 200 sampled records, per guest user), `GUEST_ROW_CAUSES`. Use for any question of what guests can read.
- src/checks/support/integrationAccounts.ts: `resolveIntegrationAccounts`, `truncationDisclosure`, `SERVICE_LIKE_CLAUSES`. Use to find integration and service accounts.
- src/checks/support/agentGraph.ts: `loadAgentGraph` (Agentforce planners, topics, actions as the Tooling API exposes them).
- src/checks/support/missingObject.ts: `isMissingObjectError`, `queryIfPresent` (absent object means empty; permission errors still throw).
- src/checks/support/schema.ts: `fieldsOf`, `presentFields`, `hasField` (describe before querying edition-dependent fields).
- src/checks/permCatalog.ts: `DANGEROUS_PERMS`, `PERM_BY_KEY` (high-risk permission vocabulary).
- src/checks/CheckEngine.ts: `CheckEngine` (runs checks, cache-order validation, inconclusive handling).

Findings and scoring, src/findings:

- src/findings/Finding.ts: `Finding`, `AffectedItem`.
- src/findings/CheckMeta.ts: `CHECK_META`, `getCheckMeta` (per-check effort tier and impact sentence).
- src/findings/scoring.ts: `buildAuditResult` (A-F grade); config in src/findings/ScoringConfig.ts (`DEFAULT_SCORING_CONFIG`, `scoringConfigSchema`) and src/findings/loadScoringConfig.ts.
- src/findings/coverage.ts: `evidenceCoverage`, `coverageSummary`, `coverageAdvice`, `MIN_COVERAGE_FOR_A`.
- src/findings/digest.ts: `buildDigest` (`--digest` output).
- src/findings/exitCode.ts: `resolveExitCode`, `violationsFor`, `EXIT_OK`, `EXIT_FINDINGS`, `EXIT_INCONCLUSIVE`.
- src/findings/unknownMetrics.ts: `unknownMetrics`.
- src/findings/AuditResult.ts: `AuditResult`.

Other reusable code:

- src/lib/wire.ts: `buildApiClients`, `resolveOrgInfo`, `buildAuditContext`.
- src/lib/apiErrorText.ts: `apiErrorText` (code, status and message as one string, for sf-core 0.12 errors).
- src/lib/apexRefs.ts: `referencesCallout` (whole-token `callout:<name>` match).
- src/lib/packageInfo.ts: `packageInfo`.
- src/waivers: `WaiverLoader`, `applyWaivers`, `waiversConfigSchema`, `MAX_WAIVER_DAYS` (accepted-risk waivers).
- src/history: `HistoryStore`, `computeDiff`, `shouldArchiveHistory`, `isCiEnvironment`, `METRIC_META`, `metricDirection`.
- src/preflight: `AUDIT_PERMISSIONS`, `permissionLabelsFor`, `buildPreflight`, `checksRequiring`, `readEffectivePermissions`.
- src/incident/csv.ts: `filterLogFile`, `csvLine`; src/incident/ipRanges.ts: `loadIpRanges`, `parseIpRangeFile`; src/incident/bundleIo.ts: `loadBundle`, `writeJsonAtomic`, `sha256File`.
- src/timeline/loadCaptures.ts: `loadCaptures`, `parseCsv`, `discoverCapturedOrgs`; src/timeline/normalise.ts: `normaliseRow`.
- From `@cclabsnz/sf-core` (do not copy into this repo): repositories (`ApexRepository`, `FlowRepository`), API clients, `AuditContext`, `AuditCache`, `esc`, `STRICT_CSP_META`, `secureFs`, `pullEventLogs`, `EventBaselineStore`, `describeFields`, `isApiError`, branding helpers.

## Frameworks and mappings

| Mapping | What it holds | Where |
|---|---|---|
| Compliance control map | Check id to controls across frameworks: `CHECK_CONTROL_MAP` | src/compliance/mapping.ts |
| Framework catalogs | OWASP, OWASP LLM, SOC 2, ISO 27001, SBS, NZISM, HISO 10029, NZ Privacy Act, HIPAA, GDPR; `ALL_CONTROLS`, `getControl` | src/compliance/catalogs/ |
| Framework packs | `universal`, `nz`, `all` for `--frameworks`; `resolveFrameworks`, `resolveControls`, `getComplianceTags` | src/compliance/resolve.ts |
| STRIDE | `CHECK_STRIDE_MAP` | src/threats/stride.ts |
| LINDDUN | `CHECK_LINDDUN_MAP` | src/threats/linddun.ts |
| Threat taxonomy types | `STRIDE_CATEGORIES`, `LINDDUN_CATEGORIES`, names | src/threats/types.ts |
| Threat view | `buildThreatView` (per-category status for reports) | src/threats/view.ts |
| Per-finding threats | `threatsFor`, `withAttack` | src/threats/resolve.ts |
| MITRE ATT&CK | `ATTACK_TECHNIQUES`, `CAPABILITY_TECHNIQUES`, `DETECTION_GAP_TECHNIQUES`, `attackFor`, `techniquesForGrant`, `orderStepsByTactic` | src/threats/attack.ts |
| ATT&CK fixture | Enterprise ATT&CK extract used by tests | test/fixtures/attack/enterprise-attack-20.0-extract.json |
| Manual verification | Compliance verification worksheet | docs/compliance/verification-worksheet.md |

## Test and verification infrastructure

- Schema guard: test/unit/ist/liveOrgQueries.schema.test.ts runs every check against test/unit/ist/support/schemaCtx.ts, which rejects any query the captured schema would reject. The schema is test/fixtures/schema/developer-edition.json, captured by scripts/capture-schema.mjs (Developer Edition org only, GET requests only). The snapshot keeps picklist values (all but geography, locale, currency and encoding lists; values naming custom or namespaced components are dropped, like custom fields), and the guard rejects a filter on a value the picklist does not have, which the org would accept and silently match nothing (`RowCause = 'SharingRule'`, `Group.Type = 'AllInternal'`, `ObjectPermissions.SobjectType = 'User'`). Re-capture after an org upgrade: `node scripts/capture-schema.mjs devedition test/fixtures/schema/developer-edition.json`.
- Live guest-share fixture: test/fixtures/org/guest-share (README.md) puts a Private-OWD object, guest Read and a guest user sharing rule in a Developer Edition org, so the guest sharing-rule path can be checked against real share rows. Never use it on a client org.
- Deep-path schema guard: test/unit/ist/liveOrgQueries.deepPaths.test.ts seeds `schemaCtx(rows)` with one consistent org (a guest user who can read Lead, guest-executable Apex, a live site), so checks go past their first empty result and their deeper queries (guest share tables, GroupMember, UserRecordAccess, ApexClass versions) are validated too. It also asserts each of those queries is still sent. Add a seeded row and an expected query when a check gains a query behind an early return.
- Rule tests: test/unit/ist/*.rules.test.ts and the other tests in test/unit/ist cover the design docs in spec/ and intent/.
- Invariants: test/unit/invariants (read-only, no network egress, secure fs, exit code keeps JSON).
- Doc guards: test/unit/docs/readme-check-count.test.ts, test/unit/docs/readme-chain-list.test.ts, and test/unit/featureInventory.test.ts (this file).
- Chain tests: test/unit/chains (registry integrity, named chains, engine).
- Git hooks: .githooks/pre-commit and .githooks/commit-msg block org ids and client identifiers; .githooks/fixture-allowlist lists allowed synthetic values.
- Least-privilege permission set for the audit user: docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml.
- Config schemas: schemas/scoring-config.schema.json, schemas/waivers.schema.json; sample config/scoring.sample.json.

## Related repos

- sf-core: published as `@cclabsnz/sf-core`, the shared query, repository, API-client and report-shell layer. Consumed from the npm registry (package.json).
- sf-orgintel: `@cclabsnz/sf-orgintel`, a separate plugin that maps how an org works from metadata and behaviour data. Not a dependency of this repo.
- sf-audit-action: the GitHub Action that wraps `audit security` in CI (cclabsnz/sf-audit-action, see README.md).
