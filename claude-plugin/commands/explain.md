---
description: Explain an sf-audit check, or a finding from the latest run
argument-hint: "<check-id or finding-id>"
allowed-tools: Bash(sf audit explain:*), Bash(ls:*)
---

Explain `$ARGUMENTS` with sf-audit. Find the newest full report with `ls -t ./sf-audit-reports/sf-audit-*.json`. If there is one, run `sf audit explain $ARGUMENTS --file <that report> --json`; otherwise run `sf audit explain $ARGUMENTS --json`, which explains a check without a run. Summarise in plain language: what it is, why it matters, what it affects in this org, the attack paths it is part of, and the fix.
