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

- **Independent scans on every change.** Two static-analysis engines — [CodeQL](https://github.com/cclabsnz/sf-audit-plugin/security/code-scanning) (`security-extended`, of both the source **and** the CI workflows) and [Semgrep](https://github.com/cclabsnz/sf-audit-plugin/actions/workflows/semgrep.yml) (OWASP Top 10 + security-audit rulesets) — an [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin) supply-chain review, a PR **dependency-review** gate (vulnerabilities, plus a copyleft-license policy over the dependencies a PR adds), and a `pnpm audit` gate — plus Dependabot, and GitHub secret scanning with push protection. All GitHub Actions are pinned to commit SHAs. Each release ships a CycloneDX **SBOM**.
- **Regulated-environment readiness.** The above give reviewers a paper trail for procurement: SBOM per release, a dependency **license policy** enforced on every PR that adds a dependency, signed provenance, and independent SAST/supply-chain scans. What the policy does *not* do is re-litigate the tree that arrives with the Salesforce CLI SDK; [what third-party scanners flag in that tree](#alerts-on-the-dependency-tree) is set out below rather than left to the reader.
- **Least privilege & disclosure.** See [PERMISSIONS.md](../PERMISSIONS.md) for the minimal access it needs and [SECURITY.md](../SECURITY.md) for private vulnerability reporting.

## What third-party scanners flag, and why

[Socket](https://socket.dev/npm/package/@cclabsnz/sf-audit) raises two **supply-chain risk** alerts against this package itself. Neither is a vulnerability — both are behavioural heuristics — and rather than suppress them quietly, here is exactly what triggers each and how you can confirm it. The triage is committed as [`socket.yml`](../socket.yml). Socket's separate **Dependencies** tab is covered [further down](#alerts-on-the-dependency-tree).

| Alert | What triggers it | Why it is expected |
| --- | --- | --- |
| **Filesystem access** | `node:fs` reads and writes | It is a CLI that writes your audit reports (HTML/MD/JSON) to disk and reads local inputs: report-branding overrides, event-log baselines under `~/.sf/audit-history`, and its own history archive. Every path is one you pass on the command line or the tool's own dot-directory. |
| **URL strings** | `https://` literals in the shipped code | These are inert citation links rendered as `<a href>` in reports — OWASP, NZISM, the NZ Privacy Act, GDPR, HIPAA, Te Whatu Ora and CIS-style benchmark references cited by compliance findings. They are never fetched. |

Check the second one yourself — this lists every URL in the published build:

```bash
npm pack @cclabsnz/sf-audit && tar xzf cclabsnz-sf-audit-*.tgz
grep -rhoE 'https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[^"'"'"'`,;) ]*' package/lib | sort -u
```

As of v1.12.0 that prints twelve results. Nine are the standards-body citations rendered as `<a href>` in compliance findings:

```
https://docs.securitybenchmark.org/controls-at-a-glance.html
https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng
https://genai.owasp.org/llm-top-10/
https://nzism.gcsb.govt.nz/ism-document
https://owasp.org/Top10/2021/
https://privacy.org.nz/privacy-act-2020/privacy-principles/
https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
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

## Alerts on the dependency tree

Socket's **Dependencies** tab is a separate list from the two alerts above, and it is longer: twenty alert types across the roughly 260 packages Socket resolves. That number invites a wrong conclusion, so here is the structural fact first.

This package declares **six** direct dependencies — `@cclabsnz/sf-core`, `@oclif/core`, `@salesforce/core`, `@salesforce/sf-plugins-core`, `chart.js` and `zod`. Every flagged package is something one of those brings with it, and all but one of them sit in the tree that any `sf` CLI plugin inherits: `@salesforce/core` (and through it `@jsforce/jsforce-node`, `faye`, `jszip`, `xml2js`, `memfs`, `pino`), `@oclif/core`, and `@salesforce/sf-plugins-core`. `chart.js` and `zod` are effectively clean. **There is no dependency this project could drop to move these numbers**, which is worth saying plainly rather than implying the tree was chosen carelessly. `pnpm audit --prod` reports no known vulnerabilities, and the CI gate above fails the build if that changes.

Five alerts are worth an actual answer rather than a count:

| Alert | Package | What is actually true |
| --- | --- | --- |
| **Copyleft License** | `jszip@3.10.1`, via `@salesforce/core` → `@jsforce/jsforce-node` | jszip declares `(MIT OR GPL-3.0-or-later)`. A disjunction is the publisher offering a choice, and this project takes the MIT branch — recorded as an explicit exception in the dependency-review policy in `.github/workflows/ci.yml`, not left implicit. Socket reports the copyleft half of that disjunction; it has not found a second licence. |
| **Non-permissive License** | `@cclabsnz/sf-core` — OFL-1.1 | This is the font licence, not a code licence. sf-core ships `src/assets/fonts/OFL.txt` beside the four embedded webfont families, because OFL §1 requires the licence text to travel with redistributed fonts. The code is Apache-2.0. This is the same bundling that makes generated reports self-contained and CDN-free. Attribution is in [`NOTICE.md`](https://github.com/cclabsnz/sf-core/blob/main/src/assets/fonts/NOTICE.md). |
| **Potential vulnerability** | `@jsonjoy.com/codegen@1.0.0`, via `memfs` ← `@salesforce/core` | Socket's note is that `compile(js)` calls `eval(js)`. It is graded medium, is flagged as pending further analysis, and has no CVE. It is a code-generation library doing code generation. |
| **AI-detected potential security risk** | `xml2js` (jsforce), `thread-stream` (pino), `powershell-utils` (`@oclif/core` → `wsl-utils`) | Heuristic findings on three long-standing packages in the Salesforce and oclif trees. `powershell-utils` is oclif's WSL detection path on Windows. |
| **Shell access** | `@jsforce/jsforce-node`, `@salesforce/core`, `powershell-utils`, `wsl-utils` | The SDK and the CLI framework can reach the shell; this plugin does not. Socket's own capability record for `@cclabsnz/sf-audit` reads `shell: false`, `eval: false`, `env: false`, `net: false` — the one network caller is `@cclabsnz/sf-core`, and its only destination is the org you authenticated against (the EventLogFile download in `RestClientImpl`). |

The remaining fifteen are volume rather than signal: 56 packages not published in five years (`lodash.isstring`, `safe-buffer`, `wordwrap`, `xmlbuilder` and similar leaves), plus counts for URL strings, environment-variable access, filesystem access and `eval` across the tree. Four "possible typosquat" hits — `ansis`, `camel-case`, `fast-string-width`, `fast-wrap-ansi` — are legitimate oclif dependencies whose names resemble more popular ones.

Confirm the attribution yourself, without taking any of the above on trust:

```bash
npm ls jszip @jsonjoy.com/codegen xml2js   # or: pnpm why jszip
npm view jszip license                     # (MIT OR GPL-3.0-or-later)
```
