<p align="center">
  <a href="https://cloudcounsel.co.nz"><img src="https://raw.githubusercontent.com/cclabsnz/sf-audit-plugin/main/assets/cloudcounsel-lockup.png" width="240" alt="CloudCounsel Ltd" /></a>
</p>

# @cclabsnz/sf-audit

[![CI](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/codeql.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/codeql.yml)
[![Semgrep](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cclabsnz/sf-audit-plugin/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin)
[![npm version](https://img.shields.io/npm/v/@cclabsnz/sf-audit)](https://www.npmjs.com/package/@cclabsnz/sf-audit)
[![npm provenance](https://img.shields.io/badge/npm-signed%20provenance-brightgreen)](https://www.npmjs.com/package/@cclabsnz/sf-audit#provenance)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Salesforce CLI (`sf`) plugin that runs a complete, **read-only** security audit against any Salesforce org, risk-scores it with an A–F grade, and turns the result into a report your security team (or your client's) can act on.

- **88 read-only checks** across identity, access, data, code, integrations, monitoring, and Agentforce / GenAI
- **Attack-chain correlation:** links individual findings into named, multi-step attack scenarios — eleven modelled chains, plus an emergent pass for combinations nobody has named yet (see [Attack chains](#attack-chains))
- **Compliance mapping:** every finding mapped to **source-verified** controls across 10 frameworks (OWASP, OWASP LLM Top 10, SOC 2, ISO/IEC 27001:2022, Security Benchmark for Salesforce, NZ Privacy Act, HISO 10029, NZISM, HIPAA Security Rule, GDPR)
- **Outputs:** a technical `html` / `md` / `json` report, or a branded, client-ready **executive report** (print-to-PDF) with priorities, remediation roadmap, and a compliance coverage matrix
- **History & diff:** archives each run and shows security-posture drift over time
- **Free event baseline:** `sf audit events pull` captures the org's free daily `EventLogFile` logs to local disk before the 1-day retention window drops them — no Event Monitoring / Shield add-on needed
- **Connected-app least-privilege:** `sf audit apps` reads the `RestApi` EventLogFile to see which objects each connected app actually uses, compares that against what its run-as user is granted, and reports the over-grant per object and read/write bit — plus a suggested least-privilege permission set
- Strictly read-only (SOQL/Tooling/REST GETs + Metadata API reads); see [PERMISSIONS.md](PERMISSIONS.md) for the least-privilege access it needs

## Installation

```bash
sf plugins install @cclabsnz/sf-audit
```

**You will be warned that this plugin is not digitally signed.** That is expected, and it is not a judgement on this plugin. Salesforce's signature verification only accepts public keys served from `developer.salesforce.com`, so no third-party plugin can satisfy it: every community plugin in the ecosystem produces the same prompt. Answer `y` to continue.

Since "trust us" is a poor answer from a tool that authenticates against your production org, the guarantees this project offers are ones you can check yourself rather than take on faith. Releases carry signed npm provenance, so you can confirm the published tarball was built from the exact public commit, and the read-only promise is enforced by a test that fails the build if a single write path appears in the source:

```bash
npm audit signatures   # reports "verified attestations" for @cclabsnz/sf-audit
```

See [Trust & verification](#trust--verification) for the full list, including the no-network-egress guard and the independent scans.

For CI or any unattended install, where an interactive prompt would hang the job, allowlist the package on the machine doing the installing:

```jsonc
// macOS and Linux: ~/.config/sf/unsignedPluginAllowList.json
// Windows:         %LOCALAPPDATA%\sf\unsignedPluginAllowList.json
["@cclabsnz/sf-audit"]
```

Or, for local development:

```bash
git clone https://github.com/cclabsnz/sf-audit-plugin.git
cd sf-audit-plugin
npm install
npm run build
sf plugins link .
```

## Usage

```bash
sf audit security --target-org <orgAlias>
```

This runs all 88 security checks against the target org and writes a report to the current directory.

List every available check id (the values you pass to `--checks`):

```bash
sf audit list
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target-org` | *(required)* | Org alias or username to audit |
| `--format` / `-f` | `html` | Output format(s), comma-separated: `html`, `md`, `json`, `executive` |
| `--output` / `-o` | `.` | Directory to write the report file |
| `--fail-on` | (none) | Exit with code 1 if any finding is at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--checks` | *(all)* | Comma-separated check IDs to run instead of all 88 (e.g. `hardcoded-credentials,apex-sharing`) |
| `--scoring-config` | (none) | Path to a custom scoring config JSON file to override weights and grade thresholds |
| `--prepared-for` | (none) | Client name for the executive report cover line |
| `--branding` | (none) | Path to a `report-branding.json` to override CloudCounsel defaults (executive format) |
| `--top` | `5` | Number of executive priorities to highlight (executive format) |
| `--frameworks` | `universal` | Compliance matrix scope (executive format): `universal` (OWASP/OWASP LLM/SOC 2/ISO 27001), `nz` (ISO/HISO/Privacy Act/NZISM), `all`, or a comma list (e.g. `owasp,owasp-llm,iso,nzism`, or `hipaa` / `gdpr` for a US healthcare or EU/UK engagement) |
| `--resolve-domains` | `false` | Makes **outbound DNS queries from this machine** to verify CSP trusted domains still resolve (flags unresolvable / parked domains as exfiltration channels). Off by default; a default run contacts **only the target org** and never reaches out to any other host. |

### Examples

```bash
# HTML report (default)
sf audit security --target-org myOrg

# Multiple formats at once
sf audit security --target-org myOrg --format html,md,json

# Write report to a specific directory
sf audit security --target-org myOrg --output ./reports

# Fail CI pipeline on HIGH or CRITICAL findings
sf audit security --target-org myOrg --fail-on HIGH

# Run only specific checks
sf audit security --target-org myOrg --checks hardcoded-credentials,apex-sharing,guest-user-access

# Guest / Experience Cloud exposure sweep — the unauthenticated data-leak surface
# (bulk-read via UI API, guest-owned records defeating Private OWD, file access, self-reg, threat detection)
sf audit security --target-org myOrg --checks guest-user-access,guest-object-exposure,guest-site-options,guest-executable-apex,experience-cloud-site,threat-detection

# Use a custom scoring config (e.g. stricter weights for your org)
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

### Executive report

`--format executive` produces a CloudCounsel-branded, print-to-PDF HTML report for clients:
grade and executive summary, top priorities with abuse/impact narratives, attack scenarios, a
risk×effort remediation roadmap, and a **compliance coverage matrix** mapping findings to framework
controls. It is fully self-contained (fonts embedded); open it and **Save as PDF**.

```bash
# Branded executive report for a client (universal compliance matrix)
sf audit security --target-org myOrg --format executive --prepared-for "Acme Health" --top 5

# NZ health/government engagement: NZ framework matrix
sf audit security --target-org myOrg --format executive --frameworks nz

# White-label / co-brand via overrides
sf audit security --target-org myOrg --format executive --branding ./report-branding.json
```

Compliance controls are mapped from authoritative, version-pinned sources (OWASP Top 10:2021,
OWASP Top 10 for LLM Applications 2025, AICPA TSC, ISO/IEC 27001:2022, the Security Benchmark for
Salesforce, NZ Privacy Act, HISO 10029, NZISM, 45 CFR Part 164 Subpart C, Regulation (EU)
2016/679). Only source-verified controls render. "No findings detected" is **not** an attestation of
compliance (see the report's Scope & Liability section).

The report file is written as `sf-audit-<orgId>-<timestamp>.<ext>` in the output directory (e.g. `sf-audit-00D000000000001-1711234567890.html`).

## What It Checks

The audit runs **88 read-only checks**. Every finding is risk-rated (CRITICAL → INFO) and mapped to controls across the compliance frameworks (see [Compliance frameworks](#compliance-frameworks)). The checks are grouped into ten domains below.

### Org Health & Configuration
| Check | What it looks for |
|-------|------------------|
| Security Health Check | Salesforce Health Check score and individual high-risk settings |
| Enhanced Domains | Enhanced Domains enabled: prevents cross-org cookie leakage and enforces URL isolation |
| Pending Release Updates | Salesforce release updates pending activation, especially those past auto-activation |
| Legacy API Versions | Apex compiled on old API versions and SOAP-based remote site integrations |
| API & Resource Limits | API request consumption against daily and concurrent limits |

### Identity & Authentication
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

### Users, Permissions & Privilege
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

### Data Access & Sharing
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

### Guest & External-Facing Access
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

### Apex & Code Security
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

### Integrations, Connected Apps & Deployments
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

### Secrets & Credential Storage
| Check | What it looks for |
|-------|------------------|
| Custom Settings & Credentials | Custom settings with credential-like names that may store secrets |
| Custom Labels Credential Exposure | API keys and tokens in globally-readable Custom Labels |

### Monitoring & Threat Detection
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

### AI & Agents (Agentforce / GenAI)
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

### Known limitations (advisory-only checks)

A small number of checks emit an **advisory** rather than a pass/fail verdict because the underlying setting is not exposed to the read APIs this plugin uses (SOQL/Tooling/REST/Metadata read):

- **Experience Cloud CSP & Lightning Web Security** — the per-site LWR Content Security Policy level and the Lightning Web Security toggle live inside the site's `ExperienceBundle`, not in a `metadata.read`-able type. The check lists live Experience sites and asks for manual verification. A true detection would require retrieving and parsing the `ExperienceBundle` (retrieve → unzip → read `config/*.json`), which is a larger capability than the current read clients; it is tracked as a future enhancement.
- **"Administrators Can Log In as Any User"** is a true detection when SecuritySettings is readable; if the Metadata client is unavailable it degrades to a manual-verification advisory.

Advisory findings are surfaced as `INFO` and never inflate the health score.

## Compliance frameworks

Findings are mapped to controls across ten security and privacy frameworks. The mapping is built on a **sourced control catalog** (each control carries its framework, **pinned version**, official title, and a citation) so a finding's compliance reference ties to an exact, defensible requirement rather than a bare tag.

| Framework | Version | Notes |
|-----------|---------|-------|
| OWASP Top 10 | 2021 | Web application risk categories |
| OWASP LLM Top 10 | 2025 | LLM/GenAI application risks (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency); mapped by the AI & Agents checks |
| SOC 2 | AICPA TSC 2017 | Common Criteria (CC6–CC9) |
| ISO/IEC 27001 | 2022 | Annex A controls |
| Security Benchmark for Salesforce (SBS) | current | Salesforce-native benchmark: [docs.securitybenchmark.org](https://docs.securitybenchmark.org) |
| NZ Privacy Act | 2020 | Information Privacy Principles (IPP 5/9/12) |
| HISO 10029 | 2022 | NZ Health Information Security Framework |
| NZISM | v3.8 | NZ Information Security Manual |
| HIPAA Security Rule | 45 CFR Part 164 Subpart C (2013 Omnibus) | Administrative (164.308) and technical (164.312) safeguards, with each implementation specification's **Required / Addressable** designation preserved. Maps the **operative** rule: the HHS NPRM of 2025-01-06 that would make encryption, MFA and segmentation mandatory is still proposed, not final |
| GDPR | Regulation (EU) 2016/679 | Art. 5(1)(f), 25, 30, 32(1)(a)/(b)/(d), 33 and 44. Mapped at paragraph level, so a finding cites the specific obligation rather than "Article 32" at large |

**Provenance gate.** Each catalogued control is marked `verified` only after its title/reference is confirmed against the authoritative source. **Controls that are not verified do not render** in the compliance matrix. Nothing ships as "compliant-to-clause" on unconfirmed data. The current verification status is tracked in [`docs/compliance/verification-worksheet.md`](docs/compliance/verification-worksheet.md).

**Framework packs.** The executive report's compliance matrix is scoped with `--frameworks`:

- `universal` *(default)*: OWASP, OWASP LLM Top 10, SOC 2, ISO 27001
- `nz`: ISO 27001, HISO 10029, NZ Privacy Act, NZISM (for NZ health/government engagements)
- `all`: every framework, including HIPAA and GDPR
- a comma list of aliases, e.g. `owasp,owasp-llm,iso,nzism` (`owasp-llm` / `llm` selects the OWASP LLM Top 10, `hipaa` the HIPAA Security Rule, `gdpr` the GDPR articles)

HIPAA and GDPR are not in either named pack, because scoping them is a jurisdictional decision rather than a default — select them explicitly for a US healthcare or EU/UK engagement:

```bash
# US healthcare engagement — HIPAA Security Rule safeguards alongside the universal set
sf audit security --target-org myOrg --format executive --frameworks owasp,soc2,iso,hipaa

# EU/UK engagement — GDPR security-of-processing obligations
sf audit security --target-org myOrg --format executive --frameworks iso,gdpr
```

> **Not an attestation.** A control rendering "No findings detected" means this audit's checks surfaced no issues mapped to it. It is **not** a statement of compliance or certification. See [Scope & Liability](#scope--liability).

**Further reading:** [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://www.softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act/) and [Why Salesforce Health Cloud needs its own security review](https://www.softwareinsights.dev/posts/salesforce-health-cloud-security-review/). More in [Further reading](docs/FURTHER-READING.md).

## Attack chains

A list of findings is not a risk assessment. Three MEDIUM findings that combine into an
unauthenticated path to bulk data matter more than a lone HIGH that leads nowhere, and reading a
report severity-by-severity hides exactly that. So every audit also correlates its findings into
**attack chains**: the specific combinations that turn separate misconfigurations into a route from
an attacker's entry point to a real outcome.

Correlation runs in two passes. **Named chains** are hand-modelled scenarios — a known pattern, with
its own narrative and remediation. Where no named chain explains a combination, an **emergent pass**
reports the remaining entry-point → outcome pairs as lower-confidence "potential attack paths", so a
novel combination is still surfaced rather than missed. Every chain lists the findings that form its
steps, and remediating **any one step breaks the chain** — which is what makes this actionable
rather than alarming.

The eleven named chains:

| Chain | Severity | Fires when |
|-------|----------|-----------|
| Unauthenticated bulk exfiltration | CRITICAL | A guest foothold combines with guest-reachable code execution, public external sharing, or a guest bulk-read surface — no login required. Reached over the site's Aura endpoint (`/s/sfsites/aura`, `aura.token=null`): `RecordUiController/ACTION$executeGraphQL` for record data, or `aura.ApexAction.execute` to invoke `@AuraEnabled` Apex that runs without sharing |
| Active guest reconnaissance against an exposed data surface | CRITICAL | `AuraRequest` / `GraphQlQueryExecution` evidence shows guests probing from anonymizer IPs, or running `totalCount`-only GraphQL sweeps against `/s/sfsites/aura` to map what is readable, **and** the org exposes objects those guests can bulk-read. Reconnaissance against a confirmed surface — likely an incident already in progress |
| Standard user to org takeover | CRITICAL | A low-trust or unauthenticated entry point combines with a privilege-escalation path: escalation permissions, Author Apex, shadow admins, delegated admin, Login-As, or a toxic permission combination |
| Credential theft to external pivot | CRITICAL | Exposed secrets (hardcoded credentials, credentials in Custom Labels, debug logs, broad CORS) combine with an egress path — a named credential, remote site, or a self-provisioned connected app |
| Prompt injection blast radius | CRITICAL | A guest-reachable Agentforce channel, an over-privileged agent run-as user, and write-capable agent actions are all present, so one injected prompt can read, alter, or destroy data across the agent's reach. Reached over the messaging host (`*.my.salesforce-scrt.com`, `/iamessage/api/v2/…`), **not** the site's Aura endpoint — the API's unauthenticated access-token flow needs only the org id and the deployment's `esDeveloperName`, both public in the widget's bootstrap |
| ForcedLeak pattern | CRITICAL | Active agents + a stale or unresolvable CSP-trusted domain + no Event Monitoring capture. The Noma Security chain (Sept 2025): re-register the lapsed domain, inject an agent into sending data to it, and nothing records it |
| SOQL injection to mass read | HIGH | Injectable dynamic SOQL combines with a bulk-readable data sink (broad sharing, unencrypted sensitive fields, public report folders, View All Data) |
| MFA bypass to privileged compromise | HIGH | Weak MFA enforcement or trusted-IP MFA bypass coincides with highly-privileged accounts, so phishing or credential stuffing reaches an admin without a second factor |
| Unmasked production PII in a weakly-controlled sandbox | HIGH | A sandbox holds populated PII fields — unmasked production data — while running weaker authentication or broader sharing than the org it was refreshed from. The data is real; only the protection is not |
| Insider bulk export without monitoring | HIGH | Data is broadly readable internally, a profile or permission set can export it en masse, **and** no monitoring would record the export — the third element is what makes it unreconstructable afterwards |
| Exploitable access with no detection coverage | MEDIUM | A real capability (unauthenticated foothold, privilege escalation, org takeover) exists while two or more of threat detection, Event Monitoring, Transaction Security and SIEM forwarding are absent. Adds no exposure — reports that existing exposure would go unobserved |

Chains appear in the technical report and drive the executive report's priorities and remediation
roadmap. A chain is only reported when **every** one of its ingredients is actually present: a clean
org produces none.

## Scope & Liability

**What this tool is.** A read-only, point-in-time configuration review. Every check uses standard Salesforce SOQL, Tooling, and REST **GET** queries only: the tool performs no DML, no metadata deployments, and never modifies the target org or its data. It runs under the permissions of the authenticated `sf` user; checks that the user cannot access are reported as *inconclusive* rather than passing silently.

**What this tool is not.** It is **not** a penetration test, a dynamic/runtime security test, or a source-code audit of managed-package internals. It does not exploit vulnerabilities, attempt privilege escalation, or guarantee detection of every misconfiguration. The Health Score and A–F grade are **prioritisation aids**, not certifications, and do not represent compliance with, or accreditation under, any standard (OWASP, SOC 2, ISO 27001, HIPAA, GDPR, or otherwise). Compliance-framework tags indicate *relevance* to a control area only.


**Point-in-time.** Results reflect org configuration **at the moment the audit ran**. Configuration drift, new customisations, and platform changes can invalidate findings at any time. Re-run regularly (see [History & Diff](docs/COMMANDS.md)).

**Authorisation.** Run this tool only against orgs you own or are **explicitly authorised in writing** to assess. You are responsible for obtaining the necessary permissions and for handling generated reports (which may contain sensitive security configuration) in accordance with your organisation's data-handling and confidentiality obligations.

**No warranty.** This software is provided "as is", without warranty of any kind, express or implied. To the maximum extent permitted by law, the authors and CloudCounsel Limited accept no liability for any loss, damage, or claim arising from use of this tool or reliance on its output. Findings are informational and should be validated by a qualified Salesforce security practitioner before any remediation action is taken.

## Trust & verification

Because this tool authenticates against production orgs, "is it safe to run?" deserves a verifiable
answer rather than a claim. Every guarantee below is something you can check yourself:

- **Read-only, enforced in CI** — a test statically fails the build if any write path appears in the source
- **No network egress** — enforced the same way; reports are fully self-contained (fonts and Chart.js inlined)
- **Signed provenance** — released from CI via npm trusted publishing (OIDC); `npm audit signatures` verifies the tarball against the public commit
- **Independent scans** — CodeQL (`security-extended`, source *and* workflows), Semgrep, OpenSSF Scorecard, a dependency-review licence gate, `pnpm audit`, Dependabot, secret scanning with push protection, SHA-pinned Actions, and a CycloneDX SBOM per release

Run the guards yourself:

```bash
npm test test/unit/invariants
npm audit signatures
```

Full detail, including why Socket raises two behavioural alerts against this package and how to
confirm each: **[docs/TRUST.md](docs/TRUST.md)**. Least-privilege access is in
[PERMISSIONS.md](PERMISSIONS.md); vulnerability reporting in [SECURITY.md](SECURITY.md).

## Scoring

Each finding carries a risk weight (CRITICAL 10, HIGH 7, MEDIUM 4, LOW 1, INFO 0). The health score is
`100 - (total weight / max possible weight) * 100`, capped at 0, and maps to an A–F grade — A needs
≥ 85 with no HIGH findings; any CRITICAL is an F.

All weights and grade thresholds are configurable without recompiling, via
`--scoring-config ./my-scoring.json`. Start from [`config/scoring.sample.json`](config/scoring.sample.json),
which lists every valid `checkWeights` key; your config is deep-merged with the defaults, so include
only what you want to change.

Grade bands, the full config shape and worked examples: **[docs/SCORING.md](docs/SCORING.md)**.

## Other commands

Beyond the audit itself, the plugin ships four commands. Each is documented in
**[docs/COMMANDS.md](docs/COMMANDS.md)**.

| Command | What it does |
|---------|--------------|
| `sf audit history` / `sf audit diff` | Every run auto-archives to `~/.sf/audit-history/{orgId}`. Show posture drift across runs as a table plus an HTML timeline, or diff any two report JSONs |
| `sf audit events pull` | Capture the org's **free** daily `EventLogFile` logs to local disk before the ~1-day retention window drops them — no Event Monitoring / Shield add-on needed. Idempotent, safe to cron |
| `sf audit timeline` | Reconstruct one actor's activity across every captured event type, entirely offline. Refuses to expand a shared identity or join on a blank field, and always reports capture coverage first |
| `sf audit apps` | Read the `RestApi` event log to compare what each connected app actually *uses* against what its run-as user is *granted*, and emit a suggested least-privilege permission set |

To triage captured logs for abuse patterns, pair `events pull` with the companion CLI
**[sfelf-triage](https://github.com/cclabsnz/sfelf-triage)**, which reads this plugin's
`~/.sf/event-baseline/<orgId>` layout directly.

## Requirements

- Node.js 18+
- Salesforce CLI (`sf`) v2+
- A least-privilege, **read-only** org user. The audit performs no writes and does **not** require `View All Data`. See **[PERMISSIONS.md](PERMISSIONS.md)** for the exact minimum permission set, what each is for, what the tool does *not* need, and a ready-to-deploy `SF Audit (Read-Only)` permission set ([`docs/permissionset/`](docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml)).

## Development

```bash
npm run build          # compile TypeScript
npm run typecheck      # type-check src + test (tsc --noEmit)
npm test               # typecheck, then run all tests
npm run test:unit      # typecheck, then unit tests only
npm run test:jest      # tests without the typecheck — fast inner loop
npm run clean          # remove compiled output
```

Jest transforms with [swc](https://swc.rs), which strips types without checking them, so
`npm run typecheck` is what catches type errors in tests — it runs ahead of Jest in
`npm test`. Use `npm run test:jest` while iterating, but don't treat it as a green run.

Maintainers: see **[docs/RELEASE.md](docs/RELEASE.md)** for the release checklist and the one-time repository-hardening steps (npm provenance token, branch protection, and the CodeQL / Scorecard setup behind the badges above).

## Further reading

Deep dives on this tool and the topics it checks, from our engineering blog
**[softwareinsights.dev](https://www.softwareinsights.dev)** — including how sf-audit works, the free
Event Monitoring baseline, guest-user exposure grading, the delivery-team access model, Agentforce
hardening after ForcedLeak, and the NZ compliance context.

Full annotated list: **[docs/FURTHER-READING.md](docs/FURTHER-READING.md)**.

## Commercial support

`sf-audit` is free and open source. If you'd like hands-on help — interpreting findings, prioritising remediation, or a full Salesforce security and architecture review — **[CloudCounsel](https://cloudcounsel.co.nz)**, the team behind this plugin, offers Salesforce security consulting. Reach us at [hello@cloudcounsel.co.nz](mailto:hello@cloudcounsel.co.nz).
