# Security Policy

`@cclabsnz/sf-audit` is a **read-only** Salesforce security audit plugin. It issues
only SOQL / Tooling / REST GET queries and never modifies an org. Even so, we take
the security of the plugin (and of the orgs it runs against) seriously.

## Supported versions

The latest published minor version receives security fixes. Please upgrade to the
newest release before reporting an issue.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following private channels:

- **GitHub private vulnerability reporting:** open the repository's **Security**
  tab and choose **Report a vulnerability** (preferred).
- **Email:** [hello@cloudcounsel.co.nz](mailto:hello@cloudcounsel.co.nz) with the
  subject line `SECURITY: sf-audit`.

Please include:

- the plugin version (`sf plugins inspect @cclabsnz/sf-audit`),
- a description of the issue and its impact,
- steps to reproduce, and
- any relevant logs (with org identifiers and secrets redacted).

## What to expect

- We aim to acknowledge a report within **5 business days**.
- We will confirm the issue, keep you updated on remediation, and credit you in the
  release notes unless you prefer to remain anonymous.
- Please give us a reasonable window to release a fix before any public disclosure.

## Scope

In scope: the plugin's code and its handling of org data, credentials, and report
output. Out of scope: vulnerabilities in Salesforce itself, in the `sf` CLI, or in
third-party dependencies (report those upstream; we will bump dependencies promptly
via Dependabot).

## Release integrity & assurance

- **Read-only, enforced.** A CI test (`test/unit/api/readonly-invariant.test.ts`)
  fails the build if any org-mutating API, HTTP write verb, or bulk/composite write
  path is introduced into the source.
- **Build provenance.** Packages are published from GitHub Actions with npm provenance;
  verify on the package's npm page or via `npm view @cclabsnz/sf-audit --json` (the
  `dist.attestations` field).
- **Static analysis & supply chain.** CodeQL and OpenSSF Scorecard run on every change,
  and a CycloneDX SBOM is attached to each GitHub Release.
- **To verify what you installed:** `sf plugins inspect @cclabsnz/sf-audit` for the
  version, then compare against the signed release and provenance attestation.
