---
description: Compare the two latest sf-audit runs
allowed-tools: Bash(sf audit diff:*), Bash(ls:*), Read
---

List the full reports with `ls -t ./sf-audit-reports/sf-audit-*.json`. If there are fewer than two, say so and suggest `/sf-audit:audit`. Otherwise run `sf audit diff <second newest> <newest> --format json --output ./sf-audit-reports` and read the JSON it writes. Report the grade movement, then what was fixed, then what is new, then what changed severity.
