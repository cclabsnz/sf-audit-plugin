---
description: Show the fix-first plan from the latest sf-audit run
allowed-tools: Bash(ls:*), Read
---

Read `./sf-audit-reports/summary.json` (run `/sf-audit:audit` first if it is missing). Present the plan: the headline, then every action grouped by wave (Start now, Next 30 days, This quarter), each with its effort, how many findings it closes and which chains (C…, P…) it breaks. End with how to explain any action's findings: `sf audit explain <finding-id> --file <newest ./sf-audit-reports/sf-audit-*.json>`.
