---
name: Bug report
about: Report a problem with a check, report output, or the CLI
title: "[bug] "
labels: bug
---

<!--
  SECURITY ISSUE? Do not file it here. See SECURITY.md for private reporting.
  Never paste org IDs, usernames, tokens, or report files containing real data.
-->

## What happened

A clear description of the bug.

## Expected behaviour

What you expected instead.

## Steps to reproduce

1. Command run (redact org alias): `sf audit security ...`
2. ...

## Affected check(s)

If a specific check is wrong (false positive / false negative), name its ID
(e.g. `privileged-access`). Run `sf audit list` for IDs.

## Environment

- Plugin version: <!-- sf plugins inspect @cclabsnz/sf-audit -->
- sf CLI version: <!-- sf version -->
- OS / Node version:

## Additional context

Logs or screenshots with all org identifiers and secrets redacted.
