---
description: Run a read-only sf-audit security audit of a Salesforce org and summarise page one
argument-hint: "[org-alias]"
allowed-tools: Bash(sf audit:*), Bash(sf plugins inspect:*), Bash(sf org list:*), Bash(mkdir:*), Read
---

Audit the Salesforce org `$ARGUMENTS` with sf-audit, following the sf-audit skill.

If no alias was given, list the orgs with `sf org list` and ask which one to audit. Check the plugin version first. Run the audit once with `--format json --output ./sf-audit-reports --json --summary`, saving the summary to `./sf-audit-reports/summary.json`. Then report the grade and why, coverage, the fix-first headline and the "Start now" actions, and the named attack paths, as the skill describes.
