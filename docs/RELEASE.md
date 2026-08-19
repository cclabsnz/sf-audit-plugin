# Release & repository-hardening runbook

How to ship `@cclabsnz/sf-audit` and keep the credibility signals (provenance, CodeQL,
OpenSSF Scorecard, read-only invariant) green. Do the one-time setup once; follow the
release checklist for every version.

## One-time setup

These make the badges live and unlock provenance. They can only be done in the GitHub UI
/ npm account — they are not in the repo.

### 1. npm Trusted Publishing (OIDC) — no stored token

The account enforces 2FA, and npm is deprecating 2FA-bypass tokens, so we publish via
**Trusted Publishing**: the workflow exchanges a GitHub OIDC id-token for a short-lived
npm credential at publish time. Nothing long-lived is stored in the repo.

1. On npmjs.com, open the **@cclabsnz/sf-audit** package → **Settings → Trusted
   Publishing → Add a publisher** (GitHub Actions):
   - Organization / user: `cclabsnz`
   - Repository: `sf-audit-plugin`
   - Workflow filename: `publish.yml`
   - Environment: *(leave blank unless you add one)*
2. That's it — no `NPM_TOKEN` secret. `publish.yml` already requests `id-token: write`,
   upgrades to a current npm CLI, and runs `npm publish --provenance`, which auto-detects
   OIDC and produces the signed provenance attestation.

> If you ever need a fallback token instead of OIDC, create a **Granular Access Token**
> (npmjs.com → Access Tokens) scoped to publish this package, store it as the `NPM_TOKEN`
> repo secret, and set `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` on the publish step.

### 2. Branch protection on `main` (Scorecard rewards this)

Repo **Settings → Branches → Add branch ruleset** (or classic branch protection) for
`main`:

- ✅ Require a pull request before merging (≥1 approval).
- ✅ Require status checks to pass — add as **required**:
  - `CI / build-test`
  - `CI / audit`
  - `CodeQL`
  - `Guard internal files / guard`
- ✅ Require branches to be up to date before merging.
- ✅ Do not allow bypassing the above (also blocks force-push / deletion).
- ✅ Require signed commits (optional, but bumps the Scorecard score).

### 3. Enable the security features

Repo **Settings → Code security**:

- ✅ **Private vulnerability reporting** (backs the channel in `SECURITY.md`).
- ✅ **Dependabot alerts** + **security updates** (Dependabot config already present).
- ✅ **CodeQL / code scanning** — the `codeql.yml` workflow feeds it; confirm default
  setup is **off** so it doesn't conflict with the advanced workflow.

### 4. First Scorecard run

Push to `main` once; `scorecard.yml` publishes to the public dashboard. The README badge
resolves after the first successful run:
<https://securityscorecards.dev/viewer/?uri=github.com/cclabsnz/sf-audit-plugin>

## Per-release checklist

> Local policy: work stops at a local commit; **you** trigger the push and the release.

1. **Version bump.** Update `version` in `package.json` (semver). Update the inventory in
   `docs/CHECKS.md` and the per-domain summary in `README.md` if the check set changed —
   `readme-check-count.test.ts` fails the build if either drifts from the registry.
2. **Changelog.** Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new heading
   for this version, linked to its release tag, and open a fresh empty `Unreleased`. The
   changelog and the GitHub Release note must say the same thing: the release note is the
   canonical published record, and `CHANGELOG.md` is what a reader finds in the repo and
   in the npm tarball. Letting them diverge is worse than having neither.
3. **Green locally.**
   ```bash
   pnpm install --frozen-lockfile
   pnpm run build      # clean tsc (src only)
   pnpm test           # typecheck (src + test), then all suites incl. read-only invariant
   pnpm audit --prod --audit-level high
   ```
   `pnpm test` runs `typecheck` first because Jest transforms with swc, which strips
   types without checking them. Don't substitute `pnpm run test:jest` here — it skips
   the type-check and will go green on code that does not compile.
4. **Commit & push** the version bump; open a PR; let CI + CodeQL go green; merge.
5. **Tag & GitHub Release.** Create a release whose tag matches the version (e.g.
   `v1.7.0`). Publishing the release triggers `publish.yml`, which:
   - re-runs build + tests,
   - `npm publish --provenance --access public`,
   - generates `sbom.cyclonedx.json` and attaches it to the release.
6. **Verify the published artifact.**
   ```bash
   npm view @cclabsnz/sf-audit version
   npm view @cclabsnz/sf-audit --json | jq '.dist.attestations'   # provenance present
   sf plugins install @cclabsnz/sf-audit
   sf plugins inspect @cclabsnz/sf-audit                           # confirms the version
   ```
   On the npm page, confirm the **"Built and signed on GitHub Actions"** provenance badge
   and that the SBOM is attached to the GitHub Release.

## Maintenance

- **Dependabot** opens weekly PRs for npm deps and GitHub Actions (including SHA-pinned
  actions — it updates both the SHA and the `# vN` comment). Merge promptly; security
  fixes arrive as their own PRs.
- **`github/codeql-action/*` bumps must be merged together.** Dependabot raises `init`,
  `analyze` and `upload-sarif` as *separate* PRs, but `init` and `analyze` both live in
  `codeql.yml`. Merging one alone leaves the workflow mismatched and CodeQL fails with
  `Loaded a configuration file for version 'X', but running version 'Y'` — and since
  `analyze (javascript-typescript)` is a required check, that blocks `main`. Combine them
  into one branch, then close the individual PRs as superseded.
- **A Dependabot alert can outlive its fix.** Check the alert's `first_patched_version`
  against what the lockfile actually resolves, not just whether an override exists — a
  `pnpm.overrides` floor pinned one patch below the fix (e.g. `^3.15.0` against a fix in
  `3.15.1`) leaves the vulnerable version installed while looking addressed. The
  `Dependabot Updates` job may also fail outright on such an alert rather than opening
  a PR, so a red job there is worth reading, not assuming.
- **If a scan goes red:** CodeQL findings appear under **Security → Code scanning**;
  Scorecard details are in the public viewer. Treat a failing **read-only invariant** test
  as a release blocker — it means a write path was introduced (see
  `test/unit/invariants/readonly-invariant.test.ts`; the intended escape hatch is
  a reviewed `// invariant:allow` line comment, used only for genuine false positives).
  Treat a failing **network-egress invariant** the same way — it means the tool, or a report
  it generates, would contact something other than the authenticated org. Every package runs
  both guards against its own `src/`, so check the failing package, not just core.

## The credibility signals at a glance

| Signal | Where | Proves |
| ------ | ----- | ------ |
| Read-only invariant | `test/unit/invariants/readonly-invariant.test.ts` (CI) | The tool cannot write to a target org |
| Network-egress invariant | `test/unit/invariants/network-egress.test.ts` (CI) | No telemetry, no LLM calls, no CDN assets in reports |
| npm provenance | `publish.yml` → npm page | Installed bytes = this public commit |
| CodeQL | `codeql.yml` → Security tab | No known SAST-detectable vulns |
| OpenSSF Scorecard | `scorecard.yml` → public dashboard | Healthy supply-chain practices |
| Dependency audit | `ci.yml` + Dependabot | No known-vulnerable dependencies |
| SBOM | `publish.yml` → release asset | Full dependency inventory per release |
