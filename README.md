<p align="center">
  <a href="https://cloudcounsel.co.nz"><img src="https://raw.githubusercontent.com/cclabsnz/sf-audit-plugin/main/assets/cloudcounsel-lockup.png" width="240" alt="CloudCounsel Ltd" /></a>
</p>

# @cclabsnz/sf-audit

[![CI](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/codeql.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/codeql.yml)
[![Semgrep](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml/badge.svg)](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cclabsnz/sf-audit-plugin/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14149/badge)](https://www.bestpractices.dev/projects/14149)
[![npm version](https://img.shields.io/npm/v/@cclabsnz/sf-audit)](https://www.npmjs.com/package/@cclabsnz/sf-audit)
[![npm provenance](https://img.shields.io/badge/npm-signed%20provenance-brightgreen)](https://www.npmjs.com/package/@cclabsnz/sf-audit#provenance)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Salesforce CLI (`sf`) plugin that runs a complete, **read-only** security audit against any Salesforce org, risk-scores it with an A–F grade, and turns the result into a report your security team (or your client's) can act on.

- **90 read-only checks** across identity, access, data, code, integrations, monitoring, and Agentforce / GenAI
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

You will be warned that the plugin is not digitally signed. That is expected and says nothing about
this plugin: Salesforce only accepts signing keys served from `developer.salesforce.com`, so no
third-party plugin can satisfy it. Answer `y`. For unattended installs, allowlisting and local
development setup are in **[docs/INSTALL.md](docs/INSTALL.md)**.

Since "trust us" is a poor answer from a tool that authenticates against your production org, the
guarantees here are checkable rather than asserted — see [Trust & verification](#trust--verification).

## Usage

```bash
sf audit security --target-org <orgAlias>
```

Runs all 90 checks and writes an HTML report to the current directory. `sf audit list` prints every
check id.

| Flag | Default | |
|------|---------|---|
| `--format` / `-f` | `html` | `html`, `md`, `json`, `executive` — comma-separated |
| `--fail-on` | (none) | Exit 1 if any finding is at or above `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`. For CI |
| `--checks` | *(all)* | Run only these check ids |
| `--frameworks` | `universal` | Compliance matrix scope for the executive report |

```bash
# Fail a pipeline on HIGH or worse
sf audit security --target-org myOrg --fail-on HIGH

# Branded, client-ready PDF-able report
sf audit security --target-org myOrg --format executive --prepared-for "Acme Health"
```

All twelve flags, more examples, and what the executive report contains:
**[docs/COMMANDS.md](docs/COMMANDS.md)**.

## What It Checks

**90 read-only checks** across ten domains. Every finding is risk-rated CRITICAL → INFO, mapped to
compliance controls, and correlated into [attack chains](#attack-chains).

| Domain | Checks |
|--------|-------:|
| Identity & Authentication | 13 |
| Users, Permissions & Privilege | 12 |
| Data Access & Sharing | 11 |
| Guest & External-Facing Access | 12 |
| Integrations, Connected Apps & Deployments | 10 |
| Monitoring & Threat Detection | 10 |
| Apex & Code Security | 9 |
| AI & Agents (Agentforce / GenAI) | 6 |
| Org Health & Configuration | 5 |
| Secrets & Credential Storage | 2 |

Full inventory, with what each check looks for: **[docs/CHECKS.md](docs/CHECKS.md)**.

A handful of checks emit an advisory rather than a verdict, because the underlying setting is not
exposed to the read APIs this tool uses. Those are listed and explained in the same document —
advisories are INFO and never inflate the health score.

## Compliance frameworks

Findings map to controls across ten frameworks: OWASP Top 10, OWASP LLM Top 10, SOC 2, ISO/IEC
27001:2022, the Security Benchmark for Salesforce, the NZ Privacy Act, HISO 10029, NZISM, the HIPAA
Security Rule, and GDPR.

The mapping is built on a **sourced catalog** — each control carries its framework, pinned version,
official title and a citation — so a finding ties to an exact, defensible requirement rather than a
bare tag. A **provenance gate** means a control renders only once its reference has been confirmed
against the authoritative source.

Scope the executive report's matrix with `--frameworks universal|nz|all`, or name them:
`--frameworks owasp,iso,hipaa`. HIPAA and GDPR are in no named pack, because jurisdiction is your
call, not a default.

> **Not an attestation.** A control showing "No findings detected" means this audit surfaced no
> issues mapped to it. It is not a statement of compliance. See [Scope & Liability](#scope--liability).

Framework versions, the packs, and the verification status of every control:
**[docs/COMPLIANCE.md](docs/COMPLIANCE.md)**.

## Attack chains

A list of findings is not a risk assessment. Three MEDIUM findings that combine into an
unauthenticated path to bulk data matter more than a lone HIGH that leads nowhere, and reading a
report severity-by-severity hides exactly that.

So every audit correlates its findings into attack chains. **Eleven named chains** are hand-modelled
scenarios — each with its own narrative and remediation, several naming the concrete request path an
attacker would use. Where no named chain explains a combination, an emergent pass reports the
remaining entry-point → outcome pairs as lower-confidence "potential attack paths", so a novel
combination is still surfaced.

Every chain lists the findings forming its steps, and remediating **any one step breaks the chain**.
A chain is reported only when every ingredient is present: a clean org produces none.

All eleven with severities and trigger conditions: **[docs/ATTACK-CHAINS.md](docs/ATTACK-CHAINS.md)**.

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

Release history is in **[CHANGELOG.md](CHANGELOG.md)**; each entry mirrors its
[GitHub Release](https://github.com/cclabsnz/sf-audit-plugin/releases), which carries the signed
provenance attestation and the CycloneDX SBOM for that build.

Project documents: **[GOVERNANCE.md](docs/GOVERNANCE.md)** (roles, decisions, continuity), **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**, **[ROADMAP.md](docs/ROADMAP.md)**, and the **[assurance case](docs/ASSURANCE-CASE.md)** — the argument, with evidence, that this tool is safe to point at a production org.

Maintainers: see **[docs/RELEASE.md](docs/RELEASE.md)** for the release checklist and the one-time repository-hardening steps (npm provenance token, branch protection, and the CodeQL / Scorecard setup behind the badges above).

## Further reading

Deep dives on this tool and the topics it checks, from our engineering blog
**[softwareinsights.dev](https://www.softwareinsights.dev)** — including how sf-audit works, the free
Event Monitoring baseline, guest-user exposure grading, the delivery-team access model, Agentforce
hardening after ForcedLeak, and the NZ compliance context.

Full annotated list: **[docs/FURTHER-READING.md](docs/FURTHER-READING.md)**.

## Commercial support

`sf-audit` is free and open source. If you'd like hands-on help — interpreting findings, prioritising remediation, or a full Salesforce security and architecture review — **[CloudCounsel](https://cloudcounsel.co.nz)**, the team behind this plugin, offers Salesforce security consulting. Reach us at [hello@cloudcounsel.co.nz](mailto:hello@cloudcounsel.co.nz).
