# Changelog

All notable changes to `@cclabsnz/sf-audit` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry mirrors the [GitHub Release](https://github.com/cclabsnz/sf-audit-plugin/releases) for that tag, which is the canonical
published note and carries the signed provenance attestation and CycloneDX SBOM for the build.

## [Unreleased]

Merged to `main`, not yet released.

### Added

- **HIPAA Security Rule and GDPR compliance catalogs** — 26 source-verified controls, taking the
  catalog from 93 to 119. HIPAA pins the operative 2013 Omnibus rule (the 2025 NPRM remains
  proposed) and preserves each implementation specification's Required/Addressable designation;
  GDPR is mapped at paragraph level. Reachable via `--frameworks hipaa`, `gdpr` or `all`, which
  previously rendered nothing for either. (#75)
- **Three attack chains** — `sandbox-pii-exposure`, `insider-bulk-exfil` and
  `undetected-compromise` — plus capability grants for 14 previously unmodelled findings, lifting
  chain coverage from roughly 30 to 43 of the 88 checks. Guest chains now name the concrete
  request path an attacker uses. (#75)

### Fixed

- **`MessagingChannel` was never readable.** The Agentforce channel check selected a
  non-existent `ChannelType` field; the resulting `INVALID_FIELD` error was swallowed by a
  defensive catch, so every org reported zero messaging channels. The field is `MessageType`.
  Channels of type `EmbeddedMessaging` or `WebChat` are now surfaced as public channel
  candidates. (#75)

### Changed

- **Publish workflow** installs the pinned npm with `--ignore-scripts` and asserts the resulting
  version, so a lifecycle script cannot run beside the OIDC publish credential and a failed
  upgrade cannot reach `npm publish`. (#76)
- **Documentation restructured.** The README is an overview (935 to 226 lines); the full check
  inventory, attack chains, compliance detail, command reference and trust material moved to
  `docs/`. Drift guards follow the tables they protect. (#75, #77)
- Dead code removed and unused declarations are now a compile error. (#79)

### Removed

- `ts-node`, which was unused — Jest 30 parses `jest.config.ts` natively. (#75)

## [v1.8.2](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.8.2) — 2026-08-10

Maintenance release. No user-facing behaviour changed — the check set, flags and report formats are identical to v1.8.1.

### Security

- **js-yaml** override raised to `^3.15.1`, closing Dependabot alert #27 (high — GHSA-5p4m-2wfm-xmqj, quadratic CPU consumption in `!!omap` resolution). Development-scope transitive dependency; not in the shipped runtime. (#64)

### Toolchain

- **TypeScript 5.9.3 → 7.0.2.** TS7 is the native compiler and no longer exposes the JavaScript compiler API ts-jest is built on, and no TS7-compatible ts-jest exists, so transforms moved to `@swc/jest`. Because swc only strips types, an explicit `pnpm run typecheck` step was added and runs ahead of jest. This also fixed a `tsconfig.test.json` config bug that had been leaving every file under `test/` out of the type-check program. (#62)
- **Pinned actions:** codeql-action v4.37.4, upload-artifact v7.0.1, action-gh-release v3.0.2. (#61)
- **@oclif/core** 4.13.0 → 4.13.2. (#54)

### Docs

- README blog links point at the canonical `www` host. (#63)

---

Build clean, 85 suites / 629 tests passing (including the read-only and network-egress invariants), `pnpm audit --prod --audit-level high` clean, 0 open Dependabot alerts.

## [v1.8.1](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.8.1) — 2026-08-05

Metadata and documentation only. No functional change to any check, and no change to what the tool does against your org.

**npm discoverability.** The package carried no keywords at all, which made it effectively invisible to npm search. Adds 17 terms spanning the plugin ecosystem (`sf-plugin`, `sfdx-plugin`, `oclif-plugin`), the problem space (`security-audit`, `compliance`, `devsecops`) and the frameworks the tool maps findings to (`owasp`, `soc2`, `iso27001`, `nzism`). Sets `homepage` and `bugs`, which were unset, so npm now links to the README and the issue tracker. The description now states the check count, attack-chain correlation, risk grading and framework coverage, and corrects the count to 88.

**The unsigned-plugin warning is now explained at the install step.** Salesforce's signature verification only accepts public keys served from `developer.salesforce.com`, with certificate pinning to that host, so no third-party plugin can be signed for it and every community plugin produces the same prompt. Previously the README handed you an install command and let you discover that warning unaided, which is a poor first impression from a security tool. It now says why the warning appears, points at the guarantees you can verify yourself (signed npm provenance, the read-only invariant test) instead of asking for trust, and documents the `unsignedPluginAllowList.json` path for CI installs where an interactive prompt would hang the job.

## [v1.8.0 — forensic timeline](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.8.0) — 2026-08-05

Adds `sf audit timeline`. Existing usage is unaffected: no command, flag or output contract
changed, the check count is the same, and the security grade is untouched.

### `sf audit timeline`

Salesforce splits one actor's activity across event types that share no common identifier. On a
real capture, **four types carry no `CLIENT_IP` column at all** — so filtering an event log by
address finds a fraction of the activity and misses every SOQL execution. Filtering by user finds
everything the *guest* user did, which on a community is everyone.

```bash
sf audit timeline --window yesterday --seed ip:203.0.113.50
```

It correlates a seed across every captured event type and writes a defensible timeline —
`timeline.csv`, `timeline.json` and `summary.md`. It runs **entirely offline** against captures
written by `sf audit events pull`, so it still works long after the org's retention window has
expired or its credentials have been revoked.

### What it refuses to do

Cross-event correlation is easy to get confidently wrong, and a wrong answer reads as evidence.

- **A blank field never joins.** A blank `REQUEST_ID` used as a key stops identifying anything and
  starts matching every row whose value is also blank.
- **A shared identity is not expanded.** A community guest user can stand for hundreds of
  visitors. Refused by default, with the evidence reported rather than applied quietly.

Every output leads with what was actually captured, because *"no rows matched"* means two
opposite things: the actor did nothing, or nobody captured the hour they did it in.

### Saying when

`--window` takes `yesterday`, `today`, `2h`, `90m`, a bare date (the whole day), a bare timestamp
(the hour containing it), or an exact ISO interval. Times are UTC. Omitting `--seed` returns the
whole window uncorrelated — where you look to find something worth seeding on. Asking for an
uncaptured window lists the days that were captured.

### Also in this release

- `@cclabsnz/sf-core` 0.3.0 — hourly and Real-Time Event capture, atomic writes
- Security overrides raised to `fast-uri` 3.1.5 and `brace-expansion` 5.0.9
- `NamedCredentialsCheck` no longer crashes, or silently matches the wrong credential, when a
  label contains regular-expression metacharacters

Full documentation in the README under *Forensic timeline*.

## [v1.7.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.7.0) — 2026-08-03

Sixty-two commits since 1.6.1. No command, flag, or output contract changed —
existing usage is unaffected.

### Shared platform layer

Flow and Apex reads now route through `@cclabsnz/sf-core`, consumed from the
registry. Report branding, fonts and HTML utilities moved there too.

sf-core 0.1.5 declares `@salesforce/core` as a **peer** dependency rather than
bundling its own. Every reference inside it is an `import type` — 4 `.d.ts`
mentions, 0 `.js` — so a runtime dependency only ever forced a second copy into
consumers and broke type unification across a major bump. sf-core now ships with
no runtime dependencies.

### Security

- Read-only invariant coverage restored, and a network-egress invariant added —
  both enforced in CI, so "cannot write to an org" and "nothing leaves the
  machine" are tested rather than asserted
- Generated reports are self-contained: no CDN fetches, so opening a report
  cannot phone out
- Org-data guard repaired. Its instance-host check had been failing open: a
  negative lookahead under `grep -E`, which ERE does not support, so the branch
  matched nothing while the step reported clean

### Dependencies

`@salesforce/core` 9, `@salesforce/sf-plugins-core` 13, jest 30, `@types/node` 26.

TypeScript stays at 5 — TS 7 is the native rewrite and no published ts-jest
supports it yet (latest peers `>=4.3 <7`).

### Repository

Flattened back to a single package now that the shared layer ships from the
registry and the intel plugin has its own repository.

## [v1.6.1](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.6.1) — 2026-07-26

Security + supply-chain assurance release. First release published via the hardened, OIDC pipeline.

### Fixes
- **fix(deps):** brace-expansion pinned to `5.0.8` — resolves high-severity DoS advisory [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg) reaching production via `@oclif/core`.
- **fix(security):** Enhanced Domains check now parses the hostname and uses anchored patterns, so a URL that merely contains `.my.salesforce.com` can no longer be misclassified (CodeQL `js/regex/missing-regexp-anchor`, high).

### Supply-chain assurance
- Published via **npm Trusted Publishing (OIDC)** with **build provenance** — the npm page shows a signed attestation linking this tarball to its source commit. No long-lived token.
- **CycloneDX SBOM** attached to this release.
- CI enforces a **read-only invariant** (build fails on any org-write path), plus CodeQL, OpenSSF Scorecard, a `pnpm audit` gate, and SHA-pinned actions with least-privilege permissions.

Install: `sf plugins install @cclabsnz/sf-audit`
