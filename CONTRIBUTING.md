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
- **Types are checked separately from tests.** Jest transforms with swc, which strips
  types without checking them, so a type error will *not* fail `npx jest`. `npm test`
  runs `npm run typecheck` (`tsc --noEmit` over `src` + `test`) first for that reason.
  `npm run test:jest` skips it when you want a fast inner loop — just don't read it as
  a green run.
- After editing commands or checks, re-run `npm run build`. `oclif.pluginType`
  is `jit` and the command dir is `lib/`, so a "missing" command usually means
  you forgot to build.

## Non-negotiable safety rules

This tool audits production orgs, so it is **strictly read-only**:

- Checks may only issue **SOQL / Tooling / REST GET** queries. No DML, no
  metadata deploys, no record modification, ever.
- Permission errors (`INSUFFICIENT_ACCESS*`) must surface as `inconclusive`
  findings, not crashes.
- Never run the plugin against a real org in tests. Verify behaviour with unit
  tests and mocked SOQL/Tooling/REST clients only.

## Adding a new check

A new check is five touch points:

1. An impl class in `src/checks/impl/` implementing `SecurityCheck`.
2. Registration in `src/checks/registry.ts` (order matters: a check's
   `dependsOnCache` must be satisfied by an earlier check's `populatesCache`;
   `CheckEngine.validateCacheOrdering()` enforces this at startup).
3. A compliance mapping entry in `src/compliance/mapping.ts` — add the check id to
   `BASE_CHECK_CONTROL_MAP` **and** to the right `DOMAIN` group, which is what earns it
   the NZ-pack and HIPAA/GDPR controls in one step.
4. A `CHECK_META` entry (effort + impact) in `src/findings/CheckMeta.ts`.
5. A unit test in `test/unit/checks/impl/` with mocked clients.

Then update the inventory in `docs/CHECKS.md` (the source-of-truth listing) and the
per-domain summary in `README.md`. Both are enforced: `readme-check-count.test.ts`
fails the build if either drifts from `src/checks/registry.ts`.

## Certificate of origin (DCO)

Every commit must carry a `Signed-off-by:` trailer matching its author:

```bash
git commit -s -m "your message"
```

This is the [Developer Certificate of Origin](https://developercertificate.org/) — your assertion
that you wrote the change, or otherwise have the right to submit it under Apache-2.0. It is not a
copyright assignment; you keep your copyright.

A CI job checks every commit in a pull request, because a missing sign-off is invisible at review
time. If you forget:

```bash
git commit --amend --signoff      # the last commit
git rebase --signoff main         # a range of commits
```

## Coding standards

The compiler carries most of the load. `strict`, `noUnusedLocals`, `noUnusedParameters` and
`noFallthroughCasesInSwitch` are **errors**, so dead code and unused parameters cannot merge.

On top of that, `pnpm run lint` runs [oxlint](https://oxc.rs/docs/guide/usage/linter) over `src`
and `test`, configured in `.oxlintrc.json` and enforced in CI. The rule set is deliberately narrow:
correctness classes the compiler does not model, not formatting. A rule that only reshuffles code
costs review attention without buying safety, and that attention is better spent on findings.

(oxlint rather than ESLint because this project is on TypeScript 7, whose native compiler no longer
exposes the JavaScript API `typescript-eslint` is built on — the same constraint that moved test
transforms to swc.)

Beyond the linter, follow the surrounding code: explicit sharing declarations in examples, `.js`
extensions on relative imports (NodeNext), and comments that explain *why* rather than restate the
code.

## Testing policy

**Every change that adds or alters behaviour ships with automated tests in the same pull
request.** New checks require a unit test with mocked SOQL/Tooling/REST clients; bug fixes
require a test that fails without the fix. Documentation-only changes are exempt, though
the counts and tables in `README.md` and `docs/` are themselves test-enforced.

This is not advisory: `build-test` is a required status check on `main`, so a pull request
whose tests do not pass cannot merge.

## Before you open a pull request

- `npm run build` is clean.
- `npm test` is green (typecheck + Jest, ESM). New/changed behaviour ships with unit tests.
- Registry ordering still validates and every new check id has a compliance
  mapping and `CHECK_META` entry.
- README counts/flags are updated if user-facing behaviour changed.
- No report artifacts (`sf-audit-*.{html,md,json}`) are staged.

## Reporting bugs and requesting features

Use the issue templates. For anything security-sensitive, **do not** open a public
issue. See [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions are licensed under the same
license as this project (see [LICENSE](LICENSE)).
