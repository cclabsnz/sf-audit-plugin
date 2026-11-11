---
name: sf-audit
description: Run and triage a read-only Salesforce security audit with the sf-audit CLI plugin. Use when the user asks to audit, security-review, assess or grade a Salesforce org, asks what to fix first in an org, wants a security finding, check or attack path explained, or wants to compare two audit runs.
---

# Auditing a Salesforce org with sf-audit

sf-audit is a read-only `sf` CLI plugin: 109 checks, an A to F grade with its reason, attack chains, and a fix-first plan. It never writes to the org. Findings are evidence to confirm in the org, not proof: say so when you report them.

## Before running

1. Check the plugin: `sf plugins inspect @cclabsnz/sf-audit --json`. It needs version 1.27.0 or later for `--summary` and `sf audit explain`. If it is missing or older, tell the user and offer `sf plugins install @cclabsnz/sf-audit` (it is unsigned, so the install asks to confirm; the user answers that prompt, not you).
2. Ask which org alias to audit if the user did not name one. `sf org list` shows the aliases. Never pick an org yourself: auditing production is the user's decision.
3. If the user has not run it before, suggest `sf audit preflight --target-org <alias>` first: it lists the permissions the audit user lacks, which otherwise show up as unassessed checks.

## Running

One run gives both the page-one summary and the full report:

```bash
sf audit security --target-org <alias> --format json --output ./sf-audit-reports --json --summary > ./sf-audit-reports/summary.json
```

- `summary.json` is the command's `--json` envelope; the summary is under `result`. It has the grade, `gradeReason`, `coverage`, `counts`, `headline`, `actions` (each with `wave`, `effort`, the finding ids it `closes`, and chain labels it `breaks`) and `attackChains` (labels C1 for named chains, P1 for potential ones).
- The full report is `./sf-audit-reports/sf-audit-<orgId>-<timestamp>.json`. Use the newest one for `explain` and `diff`.
- A run takes a few minutes. Exit code 2 means it could not run (authentication, connection or flags): report the error. 1 means `--fail-on` tripped and 3 means `--fail-on-inconclusive`; neither is a crash, and the summary is still written.
- `--checks id,id` runs a subset; checks that collect data the selection needs run too, and the command says which.

## Reporting back

Read `summary.json`, not the full report, and answer in this order:

1. **Grade and why**, from `gradeReason`, then coverage. If `coverage.percent` is below about 90, say which checks were not assessed (`coverage.notAssessed`) and that `sf audit preflight` shows why; never present an unassessed area as clean.
2. **Fix first**: the `headline`, then the "Start now" actions, each with what it closes and which chains it breaks.
3. **Attack paths**: named chains (C…) with their `breakPoint`; mention potential ones (P…) as possible but unproven.
4. Offer detail on any finding: `sf audit explain <finding-id> --file <full report>`.

Keep it short. Don't paste the JSON. Quote finding titles, not raw ids, unless the user is going to run a command with them.

## Explaining

- A check: `sf audit explain <check-id>` (works without a run).
- A finding from a run: `sf audit explain <finding-id> --file <full report json>`. It gives what it affects, the chains it is part of, and the plan action that closes it.
- A check's findings in a run: `sf audit explain <check-id> --file <full report json>`.

## Comparing runs

`sf audit diff <older.json> <newer.json> --format json --output ./sf-audit-reports` writes new, fixed and changed findings. Report the grade movement, then what was fixed, then what is new.

## Don't

- Don't run anything that writes to the org; sf-audit itself only reads.
- Don't paste org ids, user names or record data into anything outside the session.
- Don't claim a finding is confirmed: the audit reads configuration and samples; the user verifies in the org.
