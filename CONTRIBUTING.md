# Contributing to @cclabsnz/sf-audit

Thanks for your interest in improving the Salesforce Security Audit plugin. This
document covers how to get set up, the conventions the project follows, and what
a good contribution looks like.

## Getting started

This is an [oclif](https://oclif.io/) `sf` plugin written in TypeScript (ESM).

```bash
git clone https://github.com/cclabsnz/sf-audit-plugin.git
cd sf-audit-plugin
npm install
npm run build
sf plugins link .
sf audit security --target-org <alias>
```

- **Package manager:** the lockfile is `pnpm-lock.yaml`. Use `pnpm` to add
  dependencies; npm scripts (`npm run build`, `npm test`) are fine for running.
- **ESM/NodeNext:** relative imports must end in `.js` even inside `.ts` files.
- After editing commands or checks, re-run `npm run build` — `oclif.pluginType`
  is `jit` and the command dir is `lib/`, so a "missing" command usually means
  you forgot to build.

## Non-negotiable safety rules

This tool audits production orgs, so it is **strictly read-only**:

- Checks may only issue **SOQL / Tooling / REST GET** queries. No DML, no
  metadata deploys, no record modification — ever.
- Permission errors (`INSUFFICIENT_ACCESS*`) must surface as `inconclusive`
  findings, not crashes.
- Never run the plugin against a real org in tests. Verify behaviour with unit
  tests and mocked SOQL/Tooling/REST clients only.

## Adding a new check

A new check is five touch points:

1. An impl class in `src/checks/impl/` implementing `SecurityCheck`.
2. Registration in `src/checks/registry.ts` (order matters — a check's
   `dependsOnCache` must be satisfied by an earlier check's `populatesCache`;
   `CheckEngine.validateCacheOrdering()` enforces this at startup).
3. A compliance mapping entry in `src/compliance/mapping.ts`.
4. A `CHECK_META` entry (effort + impact) in `src/findings/CheckMeta.ts`.
5. A unit test in `test/unit/checks/impl/` with mocked clients.

Then update the check count and the "What It Checks" table in `README.md` — it is
the source-of-truth listing.

## Before you open a pull request

- `npm run build` is clean.
- `npm test` is green (Jest, ESM). New/changed checks ship with unit tests.
- Registry ordering still validates and every new check id has a compliance
  mapping and `CHECK_META` entry.
- README counts/flags are updated if user-facing behaviour changed.
- No report artifacts (`sf-audit-*.{html,md,json}`) are staged.

## Reporting bugs and requesting features

Use the issue templates. For anything security-sensitive, **do not** open a public
issue — see [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions are licensed under the same
license as this project (see [LICENSE](LICENSE)).
