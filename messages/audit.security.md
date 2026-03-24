# Summary

Run a comprehensive security audit against a Salesforce org.

# Flags

## target-org

The org to audit. Must be authenticated via `sf org login`.

## format

Output format: html (default), md, or json.

## output

Directory to write the report file. Defaults to the current directory.

## fail-on

Exit with code 1 if any finding is at or above this severity level.
Options: CRITICAL, HIGH, MEDIUM, LOW
