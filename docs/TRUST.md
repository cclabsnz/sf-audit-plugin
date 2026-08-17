# Trust & verification

Because this tool authenticates against production orgs, "is it safe to run?" deserves a verifiable answer, not just a claim. Here's how you can check for yourself:

- **Read-only, enforced in CI.** The "no writes to your org" promise is a passing test, not a footnote. `test/unit/invariants/readonly-invariant.test.ts` statically scans this package's entire source tree and fails the build if any jsforce mutation API, HTTP write verb, or bulk/composite write path ever appears. Every org request funnels through the client implementations in [`@cclabsnz/sf-core`](https://www.npmjs.com/package/@cclabsnz/sf-core) (`SoqlClientImpl`, `ToolingClientImpl`, `RestClientImpl`, `MetadataClientImpl`), which issue only SOQL queries, REST **GET**s, and Metadata reads. `src/lib/wire.ts` is the single place a `Connection` is turned into those clients, so there is no side path to the org.
- **Nothing phones home, enforced the same way.** `test/unit/invariants/network-egress.test.ts` fails the build on any third-party HTTP client, raw `node:http`/`https` use, telemetry/analytics/LLM endpoint, or websocket — and on any remote asset (`<script src>`, `<link href>`, `@import`) in a generated report. The only network destination is the org you authenticated against. Generated HTML reports are **fully self-contained**: webfonts are embedded as data URIs and Chart.js is inlined, so opening a report never calls out to a CDN — which matters, because reports carry sensitive findings and are often opened offline. Run both guards yourself:

  ```bash
  npm test test/unit/invariants
  ```
- **What you install matches the public source.** Releases are published from GitHub Actions via [npm trusted publishing (OIDC)](https://docs.npmjs.com/trusted-publishers) with [build provenance](https://docs.npmjs.com/generating-provenance-statements) — no long-lived token, and the npm page shows a signed attestation linking the tarball to the exact public commit that built it. Verify it yourself:

  ```bash
  npm audit signatures   # reports "verified attestations" for @cclabsnz/sf-audit
  ```

- **Independent scans on every change.** Two static-analysis engines — [CodeQL](https://github.com/cclabsnz/sf-audit-plugin/security/code-scanning) (`security-extended`, of both the source **and** the CI workflows) and [Semgrep](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml) (OWASP Top 10 + security-audit rulesets) — an [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin) supply-chain review, a PR **dependency-review** gate (vulnerabilities **and** a copyleft-license policy), and a `pnpm audit` gate — plus Dependabot, and GitHub secret scanning with push protection. All GitHub Actions are pinned to commit SHAs. Each release ships a CycloneDX **SBOM**.
- **Regulated-environment readiness.** The above give reviewers a paper trail for procurement: SBOM per release, an enforced dependency **license policy**, signed provenance, and independent SAST/supply-chain scans.
- **Least privilege & disclosure.** See [PERMISSIONS.md](../PERMISSIONS.md) for the minimal access it needs and [SECURITY.md](../SECURITY.md) for private vulnerability reporting.

## What third-party scanners flag, and why

[Socket](https://socket.dev/npm/package/@cclabsnz/sf-audit) raises two **supply-chain risk** alerts against this package. Neither is a vulnerability — both are behavioural heuristics — and rather than suppress them quietly, here is exactly what triggers each and how you can confirm it. The triage is committed as [`socket.yml`](../socket.yml).

| Alert | What triggers it | Why it is expected |
| --- | --- | --- |
| **Filesystem access** | `node:fs` reads and writes | It is a CLI that writes your audit reports (HTML/MD/JSON) to disk and reads local inputs: report-branding overrides, event-log baselines under `~/.sf/audit-history`, and its own history archive. Every path is one you pass on the command line or the tool's own dot-directory. |
| **URL strings** | `https://` literals in the shipped code | These are inert citation links rendered as `<a href>` in reports — OWASP, NZISM, the NZ Privacy Act, Te Whatu Ora and CIS-style benchmark references cited by compliance findings. They are never fetched. |

Check the second one yourself — this lists every URL in the published build:

```bash
npm pack @cclabsnz/sf-audit && tar xzf cclabsnz-sf-audit-*.tgz
grep -rhoE 'https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[^"'"'"'`,;) ]*' package/lib | sort -u
```

As of v1.8.2 that prints ten results. Seven are the standards-body citations rendered as `<a href>` in compliance findings:

```
https://docs.securitybenchmark.org/controls-at-a-glance.html
https://genai.owasp.org/llm-top-10/
https://nzism.gcsb.govt.nz/ism-document
https://owasp.org/Top10/2021/
https://privacy.org.nz/privacy-act-2020/privacy-principles/
https://www.legislation.govt.nz/act/public/2020/0031/latest/LMS23342.html
https://www.tewhatuora.govt.nz/health-services-and-programmes/cyber-hub/cyber-standards
```

The other three are this project's own attribution links, printed in report footers and CLI output rather than fetched:

```
https://cloudcounsel.co.nz                      # report footer / branding default
https://github.com/cclabsnz/sf-audit-plugin     # report footer
https://softwareinsights.dev                    # further-reading pointer in CLI output
```

No CDN, telemetry, or analytics endpoints — and the network-egress invariant above fails the build if one is ever added.
