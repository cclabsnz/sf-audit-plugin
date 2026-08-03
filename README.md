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
- **Attack-chain correlation:** links individual findings into named, multi-step attack scenarios
- **Compliance mapping:** every finding mapped to **source-verified** controls across 8 frameworks (OWASP, OWASP LLM Top 10, SOC 2, ISO/IEC 27001:2022, Security Benchmark for Salesforce, NZ Privacy Act, HISO 10029, NZISM)
- **Outputs:** a technical `html` / `md` / `json` report, or a branded, client-ready **executive report** (print-to-PDF) with priorities, remediation roadmap, and a compliance coverage matrix
- **History & diff:** archives each run and shows security-posture drift over time
- **Free event baseline:** `sf audit events pull` captures the org's free daily `EventLogFile` logs to local disk before the 1-day retention window drops them — no Event Monitoring / Shield add-on needed
- **Connected-app least-privilege:** `sf audit apps` reads the `RestApi` EventLogFile to see which objects each connected app actually uses, compares that against what its run-as user is granted, and reports the over-grant per object and read/write bit — plus a suggested least-privilege permission set
- Strictly read-only (SOQL/Tooling/REST GETs + Metadata API reads); see [PERMISSIONS.md](PERMISSIONS.md) for the least-privilege access it needs

## Installation

```bash
sf plugins install @cclabsnz/sf-audit
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
| `--frameworks` | `universal` | Compliance matrix scope (executive format): `universal` (OWASP/OWASP LLM/SOC 2/ISO 27001), `nz` (ISO/HISO/Privacy Act/NZISM), `all`, or a comma list (e.g. `owasp,owasp-llm,iso,nzism`) |
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
Salesforce, NZ Privacy Act, HISO 10029, NZISM). Only source-verified controls render. "No findings detected" is **not** an attestation of
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

Two named attack chains correlate these findings: **Prompt injection blast radius** (guest-reachable channel + over-privileged agent user + write-capable actions) and **ForcedLeak pattern** (active agents + a stale/unresolvable trusted URL + no event capture).

The five agent-specific checks stay silent in orgs where Agentforce is not enabled (the GenAI objects do not exist, so the inventory records `not-enabled` and the dependent checks return nothing). Trusted URL Hygiene runs everywhere, since the CSP allowlist is an org-wide exfiltration surface regardless of Agentforce.

### Known limitations (advisory-only checks)

A small number of checks emit an **advisory** rather than a pass/fail verdict because the underlying setting is not exposed to the read APIs this plugin uses (SOQL/Tooling/REST/Metadata read):

- **Experience Cloud CSP & Lightning Web Security** — the per-site LWR Content Security Policy level and the Lightning Web Security toggle live inside the site's `ExperienceBundle`, not in a `metadata.read`-able type. The check lists live Experience sites and asks for manual verification. A true detection would require retrieving and parsing the `ExperienceBundle` (retrieve → unzip → read `config/*.json`), which is a larger capability than the current read clients; it is tracked as a future enhancement.
- **"Administrators Can Log In as Any User"** is a true detection when SecuritySettings is readable; if the Metadata client is unavailable it degrades to a manual-verification advisory.

Advisory findings are surfaced as `INFO` and never inflate the health score.

## Compliance frameworks

Findings are mapped to controls across eight security and privacy frameworks. The mapping is built on a **sourced control catalog** (each control carries its framework, **pinned version**, official title, and a citation) so a finding's compliance reference ties to an exact, defensible requirement rather than a bare tag.

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

**Provenance gate.** Each catalogued control is marked `verified` only after its title/reference is confirmed against the authoritative source. **Controls that are not verified do not render** in the compliance matrix. Nothing ships as "compliant-to-clause" on unconfirmed data. The current verification status is tracked in [`docs/compliance/verification-worksheet.md`](docs/compliance/verification-worksheet.md).

**Framework packs.** The executive report's compliance matrix is scoped with `--frameworks`:

- `universal` *(default)*: OWASP, OWASP LLM Top 10, SOC 2, ISO 27001
- `nz`: ISO 27001, HISO 10029, NZ Privacy Act, NZISM (for NZ health/government engagements)
- `all`: every framework
- a comma list of aliases, e.g. `owasp,owasp-llm,iso,nzism` (`owasp-llm` / `llm` selects the OWASP LLM Top 10)

> **Not an attestation.** A control rendering "No findings detected" means this audit's checks surfaced no issues mapped to it. It is **not** a statement of compliance or certification. See [Scope & Liability](#scope--liability).

**Further reading:** [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act/) and [Why Salesforce Health Cloud needs its own security review](https://softwareinsights.dev/posts/salesforce-health-cloud-security-review/). More in [Further reading](#further-reading).

## Scope & Liability

**What this tool is.** A read-only, point-in-time configuration review. Every check uses standard Salesforce SOQL, Tooling, and REST **GET** queries only: the tool performs no DML, no metadata deployments, and never modifies the target org or its data. It runs under the permissions of the authenticated `sf` user; checks that the user cannot access are reported as *inconclusive* rather than passing silently.

**What this tool is not.** It is **not** a penetration test, a dynamic/runtime security test, or a source-code audit of managed-package internals. It does not exploit vulnerabilities, attempt privilege escalation, or guarantee detection of every misconfiguration. The Health Score and A–F grade are **prioritisation aids**, not certifications, and do not represent compliance with, or accreditation under, any standard (OWASP, SOC 2, ISO 27001, HIPAA, GDPR, or otherwise). Compliance-framework tags indicate *relevance* to a control area only.


**Point-in-time.** Results reflect org configuration **at the moment the audit ran**. Configuration drift, new customisations, and platform changes can invalidate findings at any time. Re-run regularly (see [History & Diff](#history--diff)).

**Authorisation.** Run this tool only against orgs you own or are **explicitly authorised in writing** to assess. You are responsible for obtaining the necessary permissions and for handling generated reports (which may contain sensitive security configuration) in accordance with your organisation's data-handling and confidentiality obligations.

**No warranty.** This software is provided "as is", without warranty of any kind, express or implied. To the maximum extent permitted by law, the authors and CloudCounsel Limited accept no liability for any loss, damage, or claim arising from use of this tool or reliance on its output. Findings are informational and should be validated by a qualified Salesforce security practitioner before any remediation action is taken.

## Trust & verification

Because this tool authenticates against production orgs, "is it safe to run?" deserves a verifiable answer, not just a claim. Here's how you can check for yourself:

- **Read-only, enforced in CI.** The "no writes to your org" promise is a passing test, not a footnote. `test/unit/invariants/readonly-invariant.test.ts` statically scans this package's entire source tree and fails the build if any jsforce mutation API, HTTP write verb, or bulk/composite write path ever appears. Every org request funnels through the core clients (`@cclabsnz/sf-core`, `src/api/*ClientImpl.ts`), which issue only SOQL queries, REST **GET**s, and Metadata reads. Each package in the monorepo runs the same guard against its own source, so nothing is covered by omission.
- **Nothing phones home, enforced the same way.** `test/unit/invariants/network-egress.test.ts` fails the build on any third-party HTTP client, raw `node:http`/`https` use, telemetry/analytics/LLM endpoint, or websocket — and on any remote asset (`<script src>`, `<link href>`, `@import`) in a generated report. The only network destination is the org you authenticated against. Generated HTML reports are **fully self-contained**: webfonts are embedded as data URIs and Chart.js is inlined, so opening a report never calls out to a CDN — which matters, because reports carry sensitive findings and are often opened offline. Run both guards yourself:

  ```bash
  pnpm --filter @cclabsnz/sf-audit test test/unit/invariants
  ```
- **What you install matches the public source.** Releases are published from GitHub Actions via [npm trusted publishing (OIDC)](https://docs.npmjs.com/trusted-publishers) with [build provenance](https://docs.npmjs.com/generating-provenance-statements) — no long-lived token, and the npm page shows a signed attestation linking the tarball to the exact public commit that built it. Verify it yourself:

  ```bash
  npm audit signatures   # reports "verified attestations" for @cclabsnz/sf-audit
  ```

- **Independent scans on every change.** Two static-analysis engines — [CodeQL](https://github.com/cclabsnz/sf-audit-plugin/security/code-scanning) (`security-extended`, of both the source **and** the CI workflows) and [Semgrep](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml) (OWASP Top 10 + security-audit rulesets) — an [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin) supply-chain review, a PR **dependency-review** gate (vulnerabilities **and** a copyleft-license policy), and a `pnpm audit` gate — plus Dependabot, and GitHub secret scanning with push protection. All GitHub Actions are pinned to commit SHAs. Each release ships a CycloneDX **SBOM**.
- **Regulated-environment readiness.** The above give reviewers a paper trail for procurement: SBOM per release, an enforced dependency **license policy**, signed provenance, and independent SAST/supply-chain scans.
- **Least privilege & disclosure.** See [PERMISSIONS.md](PERMISSIONS.md) for the minimal access it needs and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

### What third-party scanners flag, and why

[Socket](https://socket.dev/npm/package/@cclabsnz/sf-audit) raises two **supply-chain risk** alerts against this package. Neither is a vulnerability — both are behavioural heuristics — and rather than suppress them quietly, here is exactly what triggers each and how you can confirm it. The triage is committed as [`socket.yml`](../../socket.yml).

| Alert | What triggers it | Why it is expected |
| --- | --- | --- |
| **Filesystem access** | `node:fs` reads and writes | It is a CLI that writes your audit reports (HTML/MD/JSON) to disk and reads local inputs: report-branding overrides, event-log baselines under `~/.sf/audit-history`, and its own history archive. Every path is one you pass on the command line or the tool's own dot-directory. |
| **URL strings** | `https://` literals in the shipped code | These are inert citation links rendered as `<a href>` in reports — OWASP, NZISM, the NZ Privacy Act, Te Whatu Ora and CIS-style benchmark references cited by compliance findings. They are never fetched. |

Check the second one yourself — this lists every URL in the published build:

```bash
npm pack @cclabsnz/sf-audit && tar xzf cclabsnz-sf-audit-*.tgz
grep -rhoE 'https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[^"'"'"'`,;) ]*' package/lib | sort -u
```

As of v1.6.1 that prints seven results, every one a standards-body or documentation link:

```
https://docs.securitybenchmark.org/controls-at-a-glance.html
https://genai.owasp.org/llm-top-10/
https://nzism.gcsb.govt.nz/ism-document
https://owasp.org/Top10/2021/
https://privacy.org.nz/privacy-act-2020/privacy-principles/
https://www.legislation.govt.nz/act/public/2020/0031/latest/LMS23342.html
https://www.tewhatuora.govt.nz/health-services-and-programmes/cyber-hub/cyber-standards
```

No CDN, telemetry, or analytics endpoints — and the network-egress invariant above fails the build if one is ever added.

## Scoring

Each finding is assigned a risk level with a corresponding weight:

| Risk Level | Default Weight |
|------------|---------------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The health score is calculated as `100 - (total weight / max possible weight) * 100`, capped at 0.

The audit produces a **Health Score** (0–100) and a **Grade** (A–F):

| Grade | Criteria |
|-------|---------|
| A | Score ≥ 85, no HIGH findings |
| B | Score ≥ 70, ≤ 1 HIGH finding |
| C | Score ≥ 55, ≤ 3 HIGH findings |
| D | Score ≥ 40, no CRITICAL findings |
| F | Score < 40 or any CRITICAL finding |

### Custom Scoring Config

All weights and grade thresholds are configurable: no recompile needed. This is useful when your org has a different risk appetite (e.g. you want to penalise hardcoded credentials more heavily, or set stricter grade thresholds).

**Step 1:** Copy the sample config as your starting point:

```bash
cp config/scoring.sample.json my-scoring.json
```

**Step 2:** Edit the values. All three sections (`riskScores`, `checkWeights`, `gradeThresholds`) are optional: omit any section to keep the defaults.

```json
{
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {
    "hardcoded-credentials": 10,
    "guest-user-access": 10,
    "users-and-admins": 10,
    "apex-sharing": 7
  },
  "gradeThresholds": {
    "A": { "minScore": 90, "maxHigh": 0 },
    "B": { "minScore": 75, "maxHigh": 1 },
    "C": { "minScore": 60, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

The full list of valid `checkWeights` keys (one per check) is in [`config/scoring.sample.json`](config/scoring.sample.json).

**Step 3:** Pass it when running the audit:

```bash
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

Your config is deep-merged with the defaults, so you only need to include the values you want to change.

## History & Diff

Every `sf audit security` run automatically archives a JSON copy of the report to:

```
~/.sf/audit-history/{orgId}/sf-audit-{orgId}-{timestamp}.json
```

No configuration needed: archiving happens silently after each run.

### View Audit History

Show how your org's security posture has changed across multiple runs:

```bash
sf audit history --target-org myOrg
```

Prints a terminal table with score trends and writes an HTML timeline to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--reports-dir` | Custom directory containing archived reports | `~/.sf/audit-history/{orgId}` |
| `--output` | Directory to write the HTML timeline | `.` (cwd) |
| `--limit` | Maximum number of most-recent runs to show | all |

**Example output:**

```
Audit History: My Org (00D000000000001)
────────────────────────────────────────────────────────────────────────────────
  #   Date                  Score   Grade   CRIT   HIGH    MED    LOW   Δ Score
────────────────────────────────────────────────────────────────────────────────
   1  2026-03-23 15:10       64      D          1      5      8      3        —
   2  2026-04-09 11:22       81      B          0      2      5      3      +17
────────────────────────────────────────────────────────────────────────────────
  Trend: ▲ +17 over 2 audits   Best: 81 (2026-04-09 11:22)   Worst: 64 (2026-03-23 15:10)
```

### Diff Two Reports

Compare any two audit JSON files to see exactly what changed:

```bash
sf audit diff baseline.json current.json
```

Writes an HTML and JSON diff report to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--output` | Directory to write diff reports | `.` (cwd) |
| `--format` | Comma-separated formats: `html`, `json` | `html,json` |

**Example output:**

```
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....html
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....json

─────────────────────────────
  Diff Summary
─────────────────────────────
  Score delta     +17
  Grade        D → B
  New               0
  Resolved          1
─────────────────────────────
```

## Free event baseline

Salesforce's free tier exposes **Daily-interval `EventLogFile` logs** (login, API, and error
activity) on Enterprise/Unlimited/Performance editions and Developer Edition — *without* the paid
Event Monitoring / Shield add-on. The catch: on the free tier those logs are retained for only
**~1 day**. Miss a day and that day's activity is gone.

`sf audit events pull` captures them to local disk before they expire, so a daily run builds a
rolling local baseline you own:

```bash
sf audit events pull --target-org myOrg
```

It queries whatever daily event types the org actually exposes, downloads each log's CSV body, and
saves it to `~/.sf/event-baseline/{orgId}/{EventType}/{LogDate}-{Id}.csv`, plus a per-run manifest.
It is **read-only** (GET only) and **idempotent**: any log already on disk is skipped, so it is safe
to run repeatedly. Run it once a day from cron or a scheduled GitHub Action and you beat the 1-day
retention window with a growing archive — no add-on required.

```bash
# Daily cron entry (07:15) — capture yesterday's logs
15 7 * * *  sf audit events pull --target-org myOrg >> ~/.sf/event-baseline/pull.log 2>&1
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--since` | Days of `LogDate` to request (`LAST_N_DAYS` window) | `1` |
| `--types` | Restrict to specific EventTypes, comma-separated (e.g. `Login,ApiTotalUsage`) | *(all available)* |
| `--output` / `-o` | Base directory to store logs under | `~/.sf/event-baseline` |

```bash
# Backfill the last 3 days (each still subject to the org's retention)
sf audit events pull --target-org myOrg --since 3

# Only pull login and API-usage logs
sf audit events pull --target-org myOrg --types Login,ApiTotalUsage

# Store under a project-local directory instead of ~/.sf
sf audit events pull --target-org myOrg --output ./event-baseline
```

> Reading `EventLogFile` requires the **View Event Log Files** permission on the running user (this
> is in addition to the minimum read-only audit permission set). If it is missing, or the edition
> does not expose free daily logs, the command exits cleanly with an explanation rather than failing.

**Example output:**

```
Pulling free EventLogFile logs for org: My Org (00D000000000001)

─────────────────────────────
  Event Baseline Pull
─────────────────────────────
  Found           7
  Downloaded      7
  Skipped         0  (already saved)
  Total bytes  48213
─────────────────────────────
  Saved to: ~/.sf/event-baseline/00D000000000001
  Manifest: ~/.sf/event-baseline/00D000000000001/_manifests/manifest-...-....json
```

### Analyzing the captured logs

`events pull` is the collection half. To triage those `EventLogFile` CSVs for exploit and
abuse patterns, use the companion CLI **[sfelf-triage](https://github.com/cclabsnz/sfelf-triage)**.
It reads downloaded EventLogFile CSVs and emits a per-IP verdict
(`BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE`), answering *"is this guest/community IP a
vulnerability scanner or a real threat?"* — with **zero network egress** and no org connection.

sfelf-triage reads this plugin's `~/.sf/event-baseline/<orgId>` layout directly, so the two
tools chain with no glue:

```bash
sf audit events pull --target-org myOrg          # capture (this plugin)
sfelf-triage analyze ~/.sf/event-baseline/<orgId>  # triage (companion)
```

See the [sfelf-triage README](https://github.com/cclabsnz/sfelf-triage#readme) for install and usage.

## Connected-app least-privilege

Connected-app over-privilege was at the centre of the 2025-2026 wave of Salesforce data-theft
via OAuth: apps authorized with more scope than they use, and integration users with far more
object access than the app ever touches. The static checks (`connected-apps`, `connected-app-scope`,
`connected-app-inactivity`) tell you what was *granted*. `sf audit apps` tells you what is actually
*used*, so it can point at the specific access to remove.

```bash
sf audit apps --target-org myOrg --since 7
```

It reads the `RestApi` `EventLogFile` to see which objects each connected app touched, compares that
against the objects its run-as user can reach, and reports the over-grant per object and read/write
bit — plus a generated least-privilege permission set granting exactly what was observed. App IDs are
resolved to human-readable names (`AppMenuItem` / `ConnectedApplication` / a bundled standard-app
catalog / `LoginHistory` correlation), and anything unresolved is flagged loudly rather than hidden.

It is **read-only**: the suggested permission set is emitted as data, never deployed.

**Honest bounds.** `RestApi` attributes roughly half of API traffic to a connected app (the rest is
UI-API / session traffic), so *used* is a lower bound. Findings carry the observation window and
attribution rate, and revoke recommendations are suppressed below a soak window and for apps used by
many interactive users. Reading `EventLogFile` needs the **View Event Log Files** permission (the same
one `events pull` uses).

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--since` | Days of `RestApi` log to analyze | `7` |
| `--from` | Read `RestApi` CSVs from a local `events pull` baseline dir instead of downloading | *(download)* |
| `--soak` | Minimum window (days) before asserting revoke recommendations | `7` |
| `--format` | `table` / `json` / `md` | `table` |

```bash
# Reuse an events-pull baseline instead of downloading again
sf audit apps --target-org myOrg --from ~/.sf/event-baseline/00Dxxx

# Machine-readable output
sf audit apps --target-org myOrg --format json
```

## Requirements

- Node.js 18+
- Salesforce CLI (`sf`) v2+
- A least-privilege, **read-only** org user. The audit performs no writes and does **not** require `View All Data`. See **[PERMISSIONS.md](PERMISSIONS.md)** for the exact minimum permission set, what each is for, what the tool does *not* need, and a ready-to-deploy `SF Audit (Read-Only)` permission set ([`docs/permissionset/`](docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml)).

## Development

```bash
npm run build          # compile TypeScript
npm test               # run all tests
npm run test:unit      # unit tests only
npm run clean          # remove compiled output
```

Maintainers: see **[docs/RELEASE.md](docs/RELEASE.md)** for the release checklist and the one-time repository-hardening steps (npm provenance token, branch protection, and the CodeQL / Scorecard setup behind the badges above).

## Further reading

Deep dives on this tool and the topics it checks, from our engineering blog **[softwareinsights.dev](https://softwareinsights.dev)**.

**How the commands work:**

- [How sf-audit works — checks, attack chains, and compliance mapping](https://softwareinsights.dev/posts/sf-audit-61-checks-attack-chains-compliance-mapping/) — the design walkthrough behind `sf audit security`
- [Free Salesforce Event Monitoring: a baseline from EventLogFile without Shield](https://softwareinsights.dev/posts/salesforce-free-event-monitoring-eventlogfile-baseline/) — why [`sf audit events pull`](#free-event-baseline) exists and how to cron it
- [Which connected apps use less than they're granted? Ask your own logs](https://softwareinsights.dev/posts/salesforce-connected-app-least-privilege-granted-vs-used/) — the granted-vs-used method behind [`sf audit apps`](#connected-app-least-privilege)
- [Scanner or breach? Triage EventLogFile in one command](https://softwareinsights.dev/posts/salesforce-eventlogfile-guest-traffic-triage-scanner-or-breach/) — pairing an `events pull` baseline with the [sfelf-triage](https://github.com/cclabsnz/sfelf-triage) companion
- [Salesforce guest user exposure, graded by real reachability](https://softwareinsights.dev/posts/sf-audit-guest-user-exposure-reachability/) — the UI-API reachability tiering behind the [guest checks](#guest--external-facing-access)
- [sf-audit vs sf-cli-security-audit](https://softwareinsights.dev/posts/sf-audit-vs-sf-cli-security-audit/) — how this plugin differs from a configurable policy engine, and when to reach for each

**The access model the privilege checks encode** — the reasoning behind [Users, Permissions & Privilege](#users-permissions--privilege):

- [Why your developers don't need Modify All Data](https://softwareinsights.dev/posts/salesforce-developers-modify-all-data-what-they-need-instead/) — part 1 of a four-part series on delivery-team access; feeds Users & Admins and Privileged Access & Shadow Admins
- [The access model: tiers and roles](https://softwareinsights.dev/posts/salesforce-delivery-team-access-model-tiers-and-roles/) — the tiering that Separation of Duties and Privilege Escalation Permissions test against
- [Sizing the model to your team](https://softwareinsights.dev/posts/salesforce-access-model-sizing-internal-vs-external-admin-teams/) — internal vs external admins, and what the model costs to run
- [Deployable permission sets](https://softwareinsights.dev/posts/salesforce-delivery-team-deployable-permission-sets/) — the metadata and the CI identity, which the Integration / Service Accounts check inventories

**Platform changes the checks track:**

- [Hardening Agentforce against prompt injection (post-ForcedLeak)](https://softwareinsights.dev/posts/salesforce-agentforce-forcedleak-prompt-injection-hardening/) — feeds the Agentforce / GenAI checks
- [Audit your Agentforce footprint: every agent, agent user, and permission](https://softwareinsights.dev/posts/salesforce-agentforce-footprint-audit/) — the manual SOQL behind Agent Inventory
- [Agentforce agent user least privilege](https://softwareinsights.dev/posts/salesforce-agentforce-agent-user-least-privilege/) — feeds the Agent User Privilege check
- [Salesforce MFA enforcement: the revised 2026 dates](https://softwareinsights.dev/posts/salesforce-mfa-enforcement-paused-revised-dates-2026/) — feeds the MFA checks
- [The MFA enforcement admin guide](https://softwareinsights.dev/posts/salesforce-mfa-enforcement-2026-admin-guide/) — what the MFA Enforcement / Registration / Method Strength checks are measuring against
- [MFA lockout recovery and break-glass accounts](https://softwareinsights.dev/posts/salesforce-mfa-lockout-recovery-break-glass-accounts/) — the operational side of the MFA and High Assurance Session checks
- [OAuth username-password (ROPC) flow retirement in Winter '27](https://softwareinsights.dev/posts/salesforce-oauth-username-password-flow-retirement-winter-27/) — feeds the SSO Enforcement and Connected App OAuth Scopes checks
- [Email change verification retirement and Authorized Email Domains](https://softwareinsights.dev/posts/salesforce-email-change-verification-retirement-authorized-email-domains/) — feeds the Email Security check
- [Summer '26: SAML retirement & Apex secure-by-default](https://softwareinsights.dev/posts/salesforce-summer-26-saml-retirement-apex-secure-by-default/) — feeds the SSO / Apex checks
- [Salesforce security enforcement in 2026 — every change and date](https://softwareinsights.dev/posts/salesforce-security-enforcement-2026-complete-guide/) — the overall posture this tool measures
- [Report-export step-up enforcement: known issues](https://softwareinsights.dev/posts/salesforce-transaction-security-policy-report-export-known-issues/) — feeds the data-export / transaction-security checks

**Compliance and NZ context** — background for the [framework mappings](#compliance-frameworks):

- [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act/)
- [Data sovereignty for New Zealand Salesforce orgs](https://softwareinsights.dev/posts/salesforce-data-sovereignty-new-zealand/) — residency vs sovereignty, and why the `nz` framework pack exists
- [IPP 3A indirect collection notices](https://softwareinsights.dev/posts/salesforce-nz-privacy-ipp3a-indirect-collection-notice/) — feeds the NZ Privacy Act control mappings
- [Why Salesforce Health Cloud needs its own security review](https://softwareinsights.dev/posts/salesforce-health-cloud-security-review/) — the HISO 10029 context

## Commercial support

`sf-audit` is free and open source. If you'd like hands-on help — interpreting findings, prioritising remediation, or a full Salesforce security and architecture review — **[CloudCounsel](https://cloudcounsel.co.nz)**, the team behind this plugin, offers Salesforce security consulting. Reach us at [hello@cloudcounsel.co.nz](mailto:hello@cloudcounsel.co.nz).
