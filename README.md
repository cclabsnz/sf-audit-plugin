# @cclabsnz/sf-audit

A Salesforce CLI (`sf`) plugin that runs a comprehensive, **read-only** security audit against any Salesforce org, risk-scores it with an A–F grade, and turns the result into a report your security team — or your client's — can act on.

- **66 read-only checks** across identity, access, data, code, integrations, and monitoring
- **Attack-chain correlation** — links individual findings into named, multi-step attack scenarios
- **Compliance mapping** — every finding mapped to **source-verified** controls across 7 frameworks (OWASP, SOC 2, ISO/IEC 27001:2022, Security Benchmark for Salesforce, NZ Privacy Act, HISO 10029, NZISM)
- **Outputs:** a technical `html` / `md` / `json` report, or a branded, client-ready **executive report** (print-to-PDF) with priorities, remediation roadmap, and a compliance coverage matrix
- **History & diff** — archives each run and shows security-posture drift over time
- Strictly read-only (SOQL/Tooling/REST GETs); see [PERMISSIONS.md](PERMISSIONS.md) for the least-privilege access it needs

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

This runs all 66 security checks against the target org and writes a report to the current directory.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target-org` | *(required)* | Org alias or username to audit |
| `--format` / `-f` | `html` | Output format(s), comma-separated: `html`, `md`, `json`, `executive` |
| `--output` / `-o` | `.` | Directory to write the report file |
| `--fail-on` | — | Exit with code 1 if any finding is at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--checks` | *(all)* | Comma-separated check IDs to run instead of all 66 (e.g. `hardcoded-credentials,apex-sharing`) |
| `--scoring-config` | — | Path to a custom scoring config JSON file to override weights and grade thresholds |
| `--prepared-for` | — | Client name for the executive report cover line |
| `--branding` | — | Path to a `report-branding.json` to override CloudCounsel defaults (executive format) |
| `--top` | `5` | Number of executive priorities to highlight (executive format) |
| `--frameworks` | `universal` | Compliance matrix scope (executive format): `universal` (OWASP/SOC 2/ISO 27001), `nz` (ISO/HISO/Privacy Act/NZISM), `all`, or a comma list (e.g. `owasp,iso,nzism`) |

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

# Use a custom scoring config (e.g. stricter weights for your org)
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

### Executive report

`--format executive` produces a CloudCounsel-branded, print-to-PDF HTML report for clients —
grade and executive summary, top priorities with abuse/impact narratives, attack scenarios, a
risk×effort remediation roadmap, and a **compliance coverage matrix** mapping findings to framework
controls. It is fully self-contained (fonts embedded); open it and **Save as PDF**.

```bash
# Branded executive report for a client (universal compliance matrix)
sf audit security --target-org myOrg --format executive --prepared-for "Acme Health" --top 5

# NZ health/government engagement — NZ framework matrix
sf audit security --target-org myOrg --format executive --frameworks nz

# White-label / co-brand via overrides
sf audit security --target-org myOrg --format executive --branding ./report-branding.json
```

Compliance controls are mapped from authoritative, version-pinned sources (OWASP Top 10:2021,
AICPA TSC, ISO/IEC 27001:2022, the Security Benchmark for Salesforce, NZ Privacy Act, HISO 10029,
NZISM). Only source-verified controls render; "No findings detected" is **not** an attestation of
compliance (see the report's Scope & Liability section).

The report file is written as `sf-audit-<orgId>-<timestamp>.<ext>` in the output directory (e.g. `sf-audit-00D000000000001-1711234567890.html`).

## What It Checks

The audit runs **66 read-only checks**. Every finding is risk-rated (CRITICAL → INFO) and mapped to controls across the compliance frameworks (see [Compliance frameworks](#compliance-frameworks)). The checks are grouped into nine domains below.

### Org Health & Configuration
| Check | What it looks for |
|-------|------------------|
| Security Health Check | Salesforce Health Check score and individual high-risk settings |
| Enhanced Domains | Enhanced Domains enabled — prevents cross-org cookie leakage and enforces URL isolation |
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

### Data Access & Sharing
| Check | What it looks for |
|-------|------------------|
| OWD Sharing Model | Org-wide defaults for Account, Contact, Opportunity, Case, Lead (internal + external) |
| Field-Level Security | Sensitive fields (SSN, credit card, tax ID) exposed to broad permission sets |
| Public Group Sharing | Sharing rules that grant access to All Internal Users |
| Report Folder Public Access | Report folders any authenticated user can view |
| Field History Tracking | History tracking enabled on sensitive standard objects |
| Data Classification & Encryption | Field data classification usage and Shield Platform Encryption |
| Flows Without Sharing | Active flows running in system context without sharing enforcement |
| Content Distribution Links | Public file links missing expiry or passwords, and stale records |
| Public Static Resources & Documents | Documents marked externally available (anonymous URL access) and static resources cached publicly |

### Guest & External-Facing Access
| Check | What it looks for |
|-------|------------------|
| Guest User Access | Object permissions and sharing rules granted to unauthenticated guests |
| Guest-Executable Apex | Apex that guest profiles can run, flagging `without sharing` classes |
| Experience Cloud Sites | Live sites with self-registration enabled and guest user presence |
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
| SIEM Integration Signals | Evidence of SIEM or external monitoring integration |

## Compliance frameworks

Findings are mapped to controls across seven security and privacy frameworks. The mapping is built on a **sourced control catalog** — each control carries its framework, **pinned version**, official title, and a citation — so a finding's compliance reference ties to an exact, defensible requirement rather than a bare tag.

| Framework | Version | Notes |
|-----------|---------|-------|
| OWASP Top 10 | 2021 | Web application risk categories |
| SOC 2 | AICPA TSC 2017 | Common Criteria (CC6–CC9) |
| ISO/IEC 27001 | 2022 | Annex A controls |
| Security Benchmark for Salesforce (SBS) | current | Salesforce-native benchmark — [docs.securitybenchmark.org](https://docs.securitybenchmark.org) |
| NZ Privacy Act | 2020 | Information Privacy Principles (IPP 5/9/12) |
| HISO 10029 | 2022 | NZ Health Information Security Framework |
| NZISM | v3.8 | NZ Information Security Manual |

**Provenance gate.** Each catalogued control is marked `verified` only after its title/reference is confirmed against the authoritative source. **Controls that are not verified do not render** in the compliance matrix — nothing ships as "compliant-to-clause" on unconfirmed data. The current verification status is tracked in [`docs/compliance/verification-worksheet.md`](docs/compliance/verification-worksheet.md).

**Framework packs.** The executive report's compliance matrix is scoped with `--frameworks`:

- `universal` *(default)* — OWASP, SOC 2, ISO 27001
- `nz` — ISO 27001, HISO 10029, NZ Privacy Act, NZISM (for NZ health/government engagements)
- `all` — every framework
- a comma list of aliases, e.g. `owasp,iso,nzism`

> **Not an attestation.** A control rendering "No findings detected" means this audit's checks surfaced no issues mapped to it — it is **not** a statement of compliance or certification. See [Scope & Liability](#scope--liability).

**Further reading:** [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://www.softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act) and [Why Salesforce Health Cloud needs its own security review](https://www.softwareinsights.dev/posts/salesforce-health-cloud-security-review).

## Scope & Liability

**What this tool is.** A read-only, point-in-time configuration review. Every check uses standard Salesforce SOQL, Tooling, and REST **GET** queries only — the tool performs no DML, no metadata deployments, and never modifies the target org or its data. It runs under the permissions of the authenticated `sf` user; checks that the user cannot access are reported as *inconclusive* rather than passing silently.

**What this tool is not.** It is **not** a penetration test, a dynamic/runtime security test, or a source-code audit of managed-package internals. It does not exploit vulnerabilities, attempt privilege escalation, or guarantee detection of every misconfiguration. The Health Score and A–F grade are **prioritisation aids**, not certifications, and do not represent compliance with, or accreditation under, any standard (OWASP, SOC 2, ISO 27001, HIPAA, GDPR, or otherwise). Compliance-framework tags indicate *relevance* to a control area only.

**Point-in-time.** Results reflect org configuration **at the moment the audit ran**. Configuration drift, new customisations, and platform changes can invalidate findings at any time. Re-run regularly (see [History & Diff](#history--diff)).

**Authorisation.** Run this tool only against orgs you own or are **explicitly authorised in writing** to assess. You are responsible for obtaining the necessary permissions and for handling generated reports — which may contain sensitive security configuration — in accordance with your organisation's data-handling and confidentiality obligations.

**No warranty.** This software is provided "as is", without warranty of any kind, express or implied. To the maximum extent permitted by law, the authors and CloudCounsel Limited accept no liability for any loss, damage, or claim arising from use of this tool or reliance on its output. Findings are informational and should be validated by a qualified Salesforce security practitioner before any remediation action is taken.

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

All weights and grade thresholds are configurable — no recompile needed. This is useful when your org has a different risk appetite (e.g. you want to penalise hardcoded credentials more heavily, or set stricter grade thresholds).

**Step 1** — Copy the sample config as your starting point:

```bash
cp config/scoring.sample.json my-scoring.json
```

**Step 2** — Edit the values. All three sections (`riskScores`, `checkWeights`, `gradeThresholds`) are optional — omit any section to keep the defaults.

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

**Step 3** — Pass it when running the audit:

```bash
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

Your config is deep-merged with the defaults, so you only need to include the values you want to change.

## History & Diff

Every `sf audit security` run automatically archives a JSON copy of the report to:

```
~/.sf/audit-history/{orgId}/sf-audit-{orgId}-{timestamp}.json
```

No configuration needed — archiving happens silently after each run.

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
