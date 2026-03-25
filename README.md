# @cclabsnz/sf-audit

A Salesforce CLI (`sf`) plugin that runs a comprehensive security audit against any Salesforce org and produces an HTML, Markdown, or JSON report.

## Installation

```bash
sf plugins install @cclabsnz/sf-audit
```

Or, for local development:

```bash
git clone https://github.com/cclabsnz/sf-audit-plugin.git
cd cloudcounsel-sf-plugin-audit
npm install
npm run build
sf plugins link .
```

## Usage

```bash
sf audit security --target-org <orgAlias>
```

This runs all 22 security checks against the target org and writes a report to the current directory.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target-org` | *(required)* | Org alias or username to audit |
| `--format` / `-f` | `html` | Output format(s), comma-separated: `html`, `md`, `json` |
| `--output` / `-o` | `.` | Directory to write the report file |
| `--fail-on` | — | Exit with code 1 if any finding is at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |

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
```

The report file is written as `sf-audit-<orgId>-<timestamp>.<ext>` in the output directory (e.g. `sf-audit-00D000000000001-1711234567890.html`).

## What It Checks

The audit runs 22 checks across 6 categories:

### Org Health
| Check | What it looks for |
|-------|------------------|
| Health Check | Salesforce Health Check score and individual risk items |
| Password & Session Policy | Weak password requirements, session timeout, MFA gaps |

### Identity & Access
| Check | What it looks for |
|-------|------------------|
| Users & Admins | Users with system-wide permissions (ModifyAllData, ViewAllData, AuthorApex) |
| Permissions | Unassigned permission sets, excessive profile count |
| IP Restrictions | Admins without IP range restrictions, connected apps with relaxed IP policies |
| Login Sessions | Failed login trends, logins from diverse IPs, recent login activity |
| Inactive Users | Active licensed users with no login in 90+ days |

### Data Security
| Check | What it looks for |
|-------|------------------|
| Sharing Model | Object-level OWD settings for Account, Contact, Opportunity, Case, Lead |
| Field Level Security | Sensitive fields (SSN, credit card, tax ID) exposed to broad permission sets |
| Guest User Access | Object permissions and sharing rules granted to unauthenticated guest users |
| Public Group Sharing | Sharing rules that grant access to All Internal Users |

### Integration Security
| Check | What it looks for |
|-------|------------------|
| Connected Apps | Apps not restricted to admin-approved users |
| Remote Sites | Raw remote site registrations without Named Credential coverage |
| Named Credentials | Named credential inventory |
| Hardcoded Credentials | Bearer tokens, Basic auth, API keys, and raw callout URLs in Apex code |

### Code & Automation
| Check | What it looks for |
|-------|------------------|
| Apex Sharing | Apex classes using `without sharing` or missing sharing declaration |
| Flows Without Sharing | Active flows running in system context without sharing enforcement |
| Scheduled Apex | Active scheduled and batch Apex jobs |
| Code Security | Org-wide Apex test coverage percentage |

### Platform
| Check | What it looks for |
|-------|------------------|
| API Limits | API request consumption vs. daily/concurrent limits |
| Audit Trail | Permission changes and Login-As events in the setup audit trail |
| Custom Settings | Custom settings with credential-like names that may store secrets |

## Scoring

Each finding is assigned a risk level with a corresponding weight:

| Risk Level | Weight |
|------------|--------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The health score is calculated as `100 - (total weight / max possible weight) * 100`, capped at 0.

Weights are configurable in [`config/scoring.json`](config/scoring.json) — no recompile needed.

The audit produces a **Health Score** (0–100) and a **Grade** (A–F):

| Grade | Criteria |
|-------|---------|
| A | Score ≥ 85, no HIGH findings |
| B | Score ≥ 70, ≤ 1 HIGH finding |
| C | Score ≥ 55, ≤ 3 HIGH findings |
| D | Score ≥ 40, no CRITICAL findings |
| F | Score < 40 or any CRITICAL finding |

## Requirements

- Node.js 18+
- Salesforce CLI (`sf`) v2+
- The authenticated org user needs at least: Read access to setup objects (User, PermissionSet, ApexClass, Flow, etc.) and access to the Tooling API.

## Development

```bash
npm run build          # compile TypeScript
npm test               # run all tests
npm run test:unit      # unit tests only
npm run clean          # remove compiled output
```
