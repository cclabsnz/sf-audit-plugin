# Summary

Run a comprehensive, read-only security audit against a Salesforce org.

# Flags

## target-org

The org to audit. Must be authenticated via `sf org login`.

## format

Output format(s), comma-separated: `html` (default), `md`, `json`, or `executive`.
The `executive` format produces a branded, print-to-PDF client report.

## output

Directory to write the report file. Defaults to the current directory.

## fail-on

Exit with code 1 if any finding is at or above this severity level.
Options: CRITICAL, HIGH, MEDIUM, LOW

## checks

Comma-separated check IDs to run instead of all checks (e.g. `hardcoded-credentials,apex-sharing`).
Run `sf audit list` to see available check IDs.

## scoring-config

Path to a custom scoring config JSON file to override severity weights, per-check
weights, and grade thresholds. Merges with the built-in defaults.

## prepared-for

Client name for the executive report cover line (executive format).

## branding

Path to a `report-branding.json` to override the default branding (executive format).

## top

Number of executive priorities to highlight (executive format). Defaults to 5.

## frameworks

Compliance matrix scope for the executive report: `universal` (default), `nz`, `all`,
or a comma list of framework aliases (e.g. `owasp,iso,nzism`).
