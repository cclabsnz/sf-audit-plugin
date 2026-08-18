# What it checks

The audit runs **88 read-only checks**. The [README](../README.md#what-it-checks) summarises them by domain; this is the full inventory. Every finding is risk-rated (CRITICAL → INFO) and mapped to controls across the compliance frameworks (see [Compliance frameworks](#compliance-frameworks)). The checks are grouped into ten domains below.

## Org Health & Configuration
| Check | What it looks for |
|-------|------------------|
| Security Health Check | Salesforce Health Check score and individual high-risk settings |
| Enhanced Domains | Enhanced Domains enabled: prevents cross-org cookie leakage and enforces URL isolation |
| Pending Release Updates | Salesforce release updates pending activation, especially those past auto-activation |
| Legacy API Versions | Apex compiled on old API versions and SOAP-based remote site integrations |
| API & Resource Limits | API request consumption against daily and concurrent limits |

## Identity & Authentication
| Check | What it looks for |
|-------|------------------|
| SSO Enforcement | Username-password logins indicating SSO is not org-wide enforced |
| My Domain Login Policy | My Domain configured and login from login.salesforce.com blocked (stops SSO bypass) |
| Internal User MFA | MFA enforcement for active internal standard users |
| MFA for External Users | MFA enforced for external/portal users with data access |
| MFA Method Registration | Active standard users with no registered MFA method |
| MFA Method Strength | Registered MFA methods classified by strength (phishing-resistant / TOTP / weak) |
| High Assurance Sessions | Admin-capable connected apps requiring short timeouts or high-assurance MFA sessions |
| Trusted IP Ranges | Trusted IP ranges that bypass MFA, including overly broad ranges |
| Login IP Restrictions | Admin profiles missing IP ranges; connected apps with relaxed IP policy |
| Password & Session Policy | Password complexity, session timeout, and MFA gaps (from Health Check) |
| Certificate Expiry | Installed certificates nearing expiry (30 / 90 / 180-day thresholds) |
| Auth Providers & External IdPs | External Auth Providers and SAML SSO configs; flags social/JIT providers that can federate in or auto-provision users |
| Session & Clickjack Hardening | Clickjack, CSRF, XSS, and content-sniffing settings read authoritatively from SecuritySettings (Health Check cache fallback) with per-setting remediation |

## Users, Permissions & Privilege
| Check | What it looks for |
|-------|------------------|
| Users & Admins | Users with system-wide permissions (ModifyAllData, ViewAllData, AuthorApex, CustomizeApplication) |
| Permissions | Unassigned permission sets and high profile counts that widen the attack surface |
| Standard Profile Usage | Active users assigned to out-of-the-box standard profiles |
| Use Any API Client | Users with the permission that bypasses API Access Control |
| Privilege Escalation Permissions | Users holding lateral-movement / persistence permission clusters |
| Privileged Access & Shadow Admins | Effective high-risk permissions per user (profile + permission sets + groups); admin-equivalent users not on the System Administrator profile |
| Separation of Duties | Toxic permission combinations a single user holds (e.g. Manage Users + Assign Permission Sets, Author Apex + Modify All Data) |
| Integration / Service Accounts | Non-human identity inventory and excess privilege |
| Inactive Users | Active licensed users with no login in 90+ days |
| Login-As & Delegated Administration | Delegated-admin groups (SOQL) and the "log in as any user" policy read from SecuritySettings — user-impersonation and scoped-escalation paths |
| Mass Data Export Access | Profiles/permission sets with Weekly Data Export, or API access combined with View/Modify All Data (bulk-exfil capability) |

## Data Access & Sharing
| Check | What it looks for |
|-------|------------------|
| OWD Sharing Model | Org-wide defaults for Account, Contact, Opportunity, Case, Lead (internal + external) |
| Field-Level Security | Sensitive fields (SSN, credit card, tax ID) exposed to broad permission sets |
| Public Group Sharing | Sharing rules that grant access to All Internal Users |
| Report Folder Public Access | Report folders any authenticated user can view |
| Field History Tracking | History tracking enabled on sensitive standard objects |
| Data Classification & Encryption | Field data classification usage and Shield Platform Encryption |
| Encryption Coverage for Sensitive Fields | Fields classified PII/PHI (ComplianceGroup) that are NOT encrypted at rest with Shield |
| Sandbox Data Masking | In sandboxes, populated PII fields (likely unmasked production data); advises running Data Mask |
| Flows Without Sharing | Active flows running in system context without sharing enforcement |
| Content Distribution Links | Public file links missing expiry or passwords, and stale records |
| Public Static Resources & Documents | Documents marked externally available (anonymous URL access) and static resources cached publicly |

## Guest & External-Facing Access
| Check | What it looks for |
|-------|------------------|
| Guest User Access | Object permissions and sharing rules granted to unauthenticated guests |
| Guest Object Exposure (Bulk Read via UI API) | Auto-discovers guest-readable objects (incl. records exposed by guest ownership despite a Private OWD), then grades them by actual UI-API reachability: objects the UI API models are CRITICAL (GraphQL-pullable), objects readable only in the sharing model but not UI-API-modelled (Calendar, AuthSession, etc.) are separated as MEDIUM, with UserRecordAccess as ground-truth read confirmation |
| Guest-Executable Apex | Apex that guest profiles can run, flagging `without sharing` classes |
| Experience Cloud Sites | Live sites with self-registration enabled and guest user presence |
| Experience Cloud Guest Site Options | Guest file access and guest member visibility on Experience Cloud sites |
| Secure Guest User Record Access | Verifies the "Secure guest user record access" enforcement is activated — the guardrail that stops guest-owned records defeating a Private OWD (complements Guest Object Exposure) |
| Guest API & Bulk Access | Guest users granted API Enabled or Bulk API Hard Delete — programmatic bulk read/delete for unauthenticated visitors |
| Classic Force.com Sites | Active classic (Visualforce) Sites and their guest users — an unauthenticated surface separate from Experience Cloud |
| Experience Cloud CSP & Lightning Web Security | Advises verifying Strict CSP and Lightning Web Security on live sites (not reliably API-readable) |
| CORS Allowlist | Wildcard or overly broad CORS allowlist origins |
| CSP Trusted Sites | Content Security Policy trusted sites with insecure HTTP (mixed-content) endpoints |

## Apex & Code Security
| Check | What it looks for |
|-------|------------------|
| Apex Sharing Declarations | Classes classified by sharing declaration (with / without / inherited / omitted) |
| Apex CRUD/FLS Enforcement | DML or SOQL performed without CRUD/FLS permission checks |
| Apex REST Endpoints | `@RestResource` classes running `without sharing` |
| Visualforce XSS | `escape="false"` and unencoded merge fields in Visualforce markup |
| Hardcoded Credentials | Bearer tokens, Basic auth, API keys, and raw callout URLs in Apex |
| Code Security & Coverage | Org-wide Apex test coverage, class/trigger counts, and SOQL injection patterns |
| Scheduled & Batch Apex | Active scheduled and batch Apex jobs |
| Anonymous Apex Audit | Anonymous Apex executed in the last 90 days (via SetupAuditTrail) |
| Apex Logging Framework | Persistent logging usage and sensitive data exposed in Apex logs |

## Integrations, Connected Apps & Deployments
| Check | What it looks for |
|-------|------------------|
| Connected Apps | Apps not restricted to admin-approved users |
| Connected App OAuth Scopes | Full OAuth-scope grants and infinite refresh-token policies |
| Inactive Connected Apps | Apps with no OAuth logins in the past 90 days |
| Named Credentials | Named credential inventory; credentials not referenced in Apex |
| External Credential Authentication | External Credentials using no authentication or a custom (non-standard) scheme |
| Remote Site Settings | Remote sites with protocol security disabled |
| Outbound Messages | Workflow outbound messages that include a session ID or post to cleartext (http://) endpoints |
| Email Security & Spoofing | Inbound email services accepting mail from any sender / running Apex unauthenticated, and org-wide send-as addresses open to all profiles |
| Installed Packages | Managed/unmanaged package inventory; unmanaged or beta packages in production |
| Deployment Identity | Designated deployment identity and uncontrolled deployment activity |

## Secrets & Credential Storage
| Check | What it looks for |
|-------|------------------|
| Custom Settings & Credentials | Custom settings with credential-like names that may store secrets |
| Custom Labels Credential Exposure | API keys and tokens in globally-readable Custom Labels |

## Monitoring & Threat Detection
| Check | What it looks for |
|-------|------------------|
| Audit Trail | Permission changes and Login-As events in the setup audit trail |
| Login Session | Failed login trends, Login-As events, and access from diverse IPs |
| Failed Login Detection | Brute-force and credential-stuffing patterns (last 7 days) |
| Transaction Security Policies | Automated threat detection and response policies configured |
| Active Debug Log Traces | Active TraceFlag records capturing logs, including high-detail traces |
| Event Monitoring | Event Monitoring enabled with logs covering 30+ days |
| Threat Detection Event Storage | Guest User Anomaly / Threat Detection event storage enabled and retaining events |
| Guest Traffic Anomaly | Scans recent EventLogFile guest requests for anonymizer/hosting source IPs, single-IP bursts, and GraphQL `totalCount` reconnaissance sweeps |
| Anomalous Successful Logins | Accounts with successful logins from an unusually high number of distinct source IPs (credential-sharing / compromise signature) |
| SIEM Integration Signals | Evidence of SIEM or external monitoring integration |

## AI & Agents (Agentforce / GenAI)
| Check | What it looks for |
|-------|------------------|
| Agent Inventory | Every Agentforce agent, its active version, and its run-as user (inventory findings); flags an active agent whose run-as identity is inactive or frozen |
| Agent User Privilege | Agent / run-as users with Modify All Data or View All Data, broad object write access, or read access to objects classified as sensitive — the data a prompt injection inherits |
| Agent Action Surface | Write-capable agent actions (Apex/Flow that create, update, or delete) and agents with an unusually large action surface |
| Agentforce Channel Exposure | Correlates active agents with the channels that reach them (Experience Cloud sites, embedded deployments, messaging channels); flags guest-reachable exposure |
| Agentforce Monitoring Coverage | Active agents running with no Event Monitoring capture and no Transaction Security policy (the monitoring gap in the ForcedLeak pattern); points at `sf audit events pull` |
| Trusted URL Hygiene | Reviews the CSP trusted-sites allowlist for non-Salesforce domains that could be repurposed as exfiltration channels; with `--resolve-domains`, DNS-checks each for unresolvable or parked entries |

Two of the named [attack chains](#attack-chains) correlate these findings specifically: **Prompt injection blast radius** (guest-reachable channel + over-privileged agent user + write-capable actions) and **ForcedLeak pattern** (active agents + a stale/unresolvable trusted URL + no event capture).

The five agent-specific checks stay silent in orgs where Agentforce is not enabled (the GenAI objects do not exist, so the inventory records `not-enabled` and the dependent checks return nothing). Trusted URL Hygiene runs everywhere, since the CSP allowlist is an org-wide exfiltration surface regardless of Agentforce.

## Known limitations (advisory-only checks)

A small number of checks emit an **advisory** rather than a pass/fail verdict because the underlying setting is not exposed to the read APIs this plugin uses (SOQL/Tooling/REST/Metadata read):

- **Experience Cloud CSP & Lightning Web Security** — the per-site LWR Content Security Policy level and the Lightning Web Security toggle live inside the site's `ExperienceBundle`, not in a `metadata.read`-able type. The check lists live Experience sites and asks for manual verification. A true detection would require retrieving and parsing the `ExperienceBundle` (retrieve → unzip → read `config/*.json`), which is a larger capability than the current read clients; it is tracked as a future enhancement.
- **"Administrators Can Log In as Any User"** is a true detection when SecuritySettings is readable; if the Metadata client is unavailable it degrades to a manual-verification advisory.

Advisory findings are surfaced as `INFO` and never inflate the health score.
