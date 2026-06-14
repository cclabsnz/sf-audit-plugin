# @cclabsnz/sf-audit — Salesforce Security Audit sf plugin

Native `sf` CLI plugin (oclif + @salesforce/sf-plugins-core, TypeScript ESM) that runs 61
read-only security checks against a Salesforce org and renders HTML/MD/JSON reports with
scoring, compliance tags, history archiving, and diffs. CloudCounsel consulting tool; v1.0.x,
published to npm, actively gaining checks.

## Commands
- `npm run build` — tsc to `lib/`
- `npm test` / `npm run test:unit` — Jest ESM (script already passes `--experimental-vm-modules`; plain `jest` fails)
- Local plugin dev: `npm run build && sf plugins link .` then `sf audit security --target-org <alias>`
- Lockfile is pnpm (`pnpm-lock.yaml`; `package-lock.json` is gitignored) — use pnpm to add deps, npm scripts to run

## Map
- `src/checks/registry.ts` — single registration point; ORDER MATTERS (see Gotchas)
- `src/checks/impl/*Check.ts` — one class per check, implements `SecurityCheck` (`src/checks/SecurityCheck.ts`)
- `src/checks/CheckEngine.ts` — runs checks, validates cache ordering at startup, converts permission errors to "inconclusive" findings
- `src/findings/` — `Finding`, scoring + grade thresholds (defaults live in code, not config/), `ComplianceMapping.ts` (OWASP/SOC2/ISO/HIPAA/GDPR tags keyed by check id)
- `src/api/` — `SoqlClient`/`ToolingClient`/`RestClient` interfaces + Impls wrapping `@salesforce/core` Connection; checks only see these via `AuditContext`
- `src/renderers/`, `src/history/` — report output; auto-archive to `~/.sf/audit-history/{orgId}`, `sf audit diff|history|list` commands in `src/commands/audit/`
- `src/chains/` — attack-chain/capability correlation across findings
- Sibling repo `../cloudcounsel-sf-audit` = the original Python prototype (`sf_security_audit.py`) this plugin is a rewrite of. Reference only — do not edit; but its `docs/superpowers/specs/2026-03-24-sf-audit-native-plugin-design.md` is THIS repo's design doc
- GitHub remote is `cclabsnz/sf-audit-plugin` (name differs from folder)

## Hard rules
- Never run the plugin against a real org or touch stored `sf` org credentials. Verify behavior with unit tests + mocked clients only.
- Checks must be strictly read-only against the org: SOQL/Tooling/REST GETs only, no DML, no metadata deploys.
- Do not remove the `overrides` block in package.json — it patches handlebars RCE (CVE-2026-33937) and brace-expansion ReDoS.
- Never commit `sf-audit-*.{html,md,json}` report artifacts (gitignored, but the repo root is littered with local ones — leave them).

## Gotchas
- Registry order is load-bearing: a check's `dependsOnCache` must be populated by an earlier check's `populatesCache`. `CheckEngine.validateCacheOrdering()` throws at startup if violated. Cache-dependent checks sit at the bottom of `CHECKS`.
- ESM everywhere: relative imports must end in `.js` even inside `.ts` files (NodeNext). Jest maps them back via `moduleNameMapper`.
- New check = 5 touch points: impl class in `src/checks/impl/`, entry in `registry.ts` (correct position), tag row in `ComplianceMapping.ts`, unit test in `test/unit/checks/impl/`, README check count. Every recent check commit shipped with its test.
- Permission errors (`INSUFFICIENT_ACCESS*`) must surface as `inconclusive: true` findings, not check crashes — preserve this when touching CheckEngine or adding error handling.
- Checks inline their own SOQL — there is no runtime query registry. (The old `config/queries/*.json` doc catalog was removed as dead/drift-prone; its consolidation design lives in `docs/superpowers/specs/2026-04-02-query-registry-consolidation-design.md` if ever revived.)
- Scoring defaults live in code (`src/findings/ScoringConfig.ts`); they are NOT loaded from a config file. `config/scoring.sample.json` is the user-facing template for the opt-in `--scoring-config <path>` flag (`loadScoringConfig` only reads a path when passed). There is no default-loaded `config/scoring.json`.
- README "What It Checks" is the source-of-truth listing (61 checks, 9 domains) and must be updated when checks are added/removed — keep the count and tables in sync with `src/checks/registry.ts`.
- `oclif.pluginType` is `jit` and `lib/commands` is the command dir — a command "missing" after edits usually means you forgot `npm run build`.

## Done means
- `npm run build` clean and `npm test` green (currently 25 suites / 159 tests, all passing)
- New/changed checks have unit tests with mocked SOQL/Tooling/REST clients
- Registry ordering still validates; ComplianceMapping has an entry for any new check id
- README counts/flags updated if user-facing behavior changed; no report artifacts staged
