# Design: Custom Scoring Config + Confluence Admin Guide

**Date:** 2026-04-01
**Status:** Approved
**Audience:** HNZ admins / ops

---

## What We're Building

Two things, in order:

1. **`--scoring-config` flag** — lets admins pass a JSON file at runtime to override risk weights, per-check weights, and grade thresholds without touching the plugin source.
2. **HNZ Confluence admin guide** — documents installation, usage, how scoring works, and how to customise it.

---

## Part 1: `--scoring-config` Flag

### CLI Change

Add to `src/commands/audit/security.ts`:

```
--scoring-config <path>   Path to a custom scoring JSON file. Merges with defaults.
```

Example usage:

```bash
sf audit security --target-org myOrg --scoring-config ./hnz-scoring.json
sf audit security --target-org HNZ_PROD --scoring-config ./hnz-scoring.json --fail-on HIGH
```

---

### Config Schema

The file supports three optional top-level keys. All are optional — only supply what you want to override.

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
    "hardcoded-credentials": 15,
    "guest-user-access": 12,
    "health-check": 3
  },
  "gradeThresholds": {
    "A": { "minScore": 85, "maxHigh": 0 },
    "B": { "minScore": 70, "maxHigh": 1 },
    "C": { "minScore": 55, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

**`riskScores`** — base weight per severity level. Used for any check not listed in `checkWeights`.

**`checkWeights`** — per-check weight override. When a check ID is listed here, its findings always use this weight regardless of their `riskLevel`. Valid check IDs:

```
apex-sharing, api-limits, audit-trail, code-security, connected-apps,
custom-settings, field-level-security, flows-without-sharing, guest-user-access,
hardcoded-credentials, health-check, inactive-users, ip-restrictions,
login-session, named-credentials, password-session-policy, permissions,
public-group-sharing, remote-sites, scheduled-apex, sharing-model, users-and-admins
```

Unknown IDs emit a `warn` and are skipped — the run continues.

**`gradeThresholds`** — conditions for each grade, evaluated A → B → C → D → F. First grade where **all** conditions are met wins. `F` is the automatic fallback if nothing else matches. Supported condition keys per grade:

| Key | Meaning |
|-----|---------|
| `minScore` | Health score must be ≥ this value |
| `maxCritical` | Number of CRITICAL findings must be ≤ this value |
| `maxHigh` | Number of HIGH findings must be ≤ this value |
| `maxMedium` | Number of MEDIUM findings must be ≤ this value |

---

### Scoring Logic Changes

**File:** `src/findings/scoring.ts`

Weight lookup per finding changes from:
```
weight = RISK_SCORES[finding.riskLevel]
```
to:
```
weight = checkWeights[finding.checkId] ?? riskScores[finding.riskLevel]
```

The `maxPossible` denominator stays as `findings.length * 10` (baseline CRITICAL weight), keeping health scores comparable across configs.

Grade evaluation moves from hardcoded `if/else` to iterating `gradeThresholds` A → B → C → D, checking each condition. `F` is the fallback.

---

### Config Loading

**File:** `src/lib/wire.ts` (or a new `src/findings/loadScoringConfig.ts`)

Steps:
1. If `--scoring-config` is provided, read and JSON-parse the file.
2. Validate with `zod`. Schema errors throw and abort the run with a clear message.
3. Warn on any `checkWeights` key not matching a known check ID.
4. Deep-merge onto built-in defaults.
5. Pass merged config into `buildAuditResult`.

---

### Sample Config File

A ready-to-use sample with all 22 checks pre-populated ships at `config/scoring.sample.json`:

```json
{
  "_comment": "Copy this file, adjust values, and pass it with --scoring-config. All sections are optional.",
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {
    "apex-sharing": 7,
    "api-limits": 4,
    "audit-trail": 4,
    "code-security": 4,
    "connected-apps": 7,
    "custom-settings": 4,
    "field-level-security": 7,
    "flows-without-sharing": 7,
    "guest-user-access": 10,
    "hardcoded-credentials": 10,
    "health-check": 7,
    "inactive-users": 4,
    "ip-restrictions": 7,
    "login-session": 4,
    "named-credentials": 1,
    "password-session-policy": 7,
    "permissions": 4,
    "public-group-sharing": 4,
    "remote-sites": 4,
    "scheduled-apex": 1,
    "sharing-model": 7,
    "users-and-admins": 10
  },
  "gradeThresholds": {
    "A": { "minScore": 85, "maxHigh": 0 },
    "B": { "minScore": 70, "maxHigh": 1 },
    "C": { "minScore": 55, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

---

## Part 2: HNZ Confluence Page

### Page Title
`sf-audit Plugin — Admin & Ops Guide`

### Structure

```
1. Overview
2. Requirements
3. Installation
4. Running an Audit
   4a. Basic usage
   4b. Sandbox vs production
   4c. All flags reference
5. Understanding Results
   5a. Health score
   5b. Grade
   5c. Finding severity levels
6. How the Score is Calculated
   6a. Formula
   6b. Risk weights
   6c. Per-check weights
   6d. Grade thresholds
7. Customising the Scoring
   7a. The --scoring-config flag
   7b. Sample file (all 22 checks, copy-paste ready)
   7c. Warning behaviour for unknown check IDs
8. CI/CD Integration
   8a. --fail-on flag
   8b. Exit codes
9. Troubleshooting
   9a. Common errors
   9b. Permissions checklist
```

### Tone
Plain English. To the point. No marketing language. Written for someone who is comfortable with CLI tools but doesn't need to know how the plugin is built internally.

---

## Files Changed

| File | Change |
|------|--------|
| `src/commands/audit/security.ts` | Add `--scoring-config` flag |
| `src/findings/scoring.ts` | Accept config param, use check weight override, config-driven grade logic |
| `src/lib/wire.ts` or new `src/findings/loadScoringConfig.ts` | Config loading, zod validation, merge |
| `config/scoring.json` | Extend with `gradeThresholds` and `checkWeights` (becomes the default) |
| `config/scoring.sample.json` | New — sample file with all 22 checks for admins to copy |
| Confluence page | New page: `sf-audit Plugin — Admin & Ops Guide` |
