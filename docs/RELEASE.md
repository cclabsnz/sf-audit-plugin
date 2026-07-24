# Release & repository-hardening runbook

How to ship `@cclabsnz/sf-audit` and keep the credibility signals (provenance, CodeQL,
OpenSSF Scorecard, read-only invariant) green. Do the one-time setup once; follow the
release checklist for every version.

## One-time setup

These make the badges live and unlock provenance. They can only be done in the GitHub UI
/ npm account — they are not in the repo.

### 1. npm publish token

1. On npmjs.com → **Access Tokens** → generate a **Granular Access Token** scoped to
   publish `@cclabsnz/sf-audit` (or a classic **Automation** token).
2. In GitHub → repo **Settings → Secrets and variables → Actions → New repository
   secret**: name `NPM_TOKEN`, value = the token.
3. `publish.yml` already requests `id-token: write`; combined with `npm publish
   --provenance` this produces the signed attestation. No other config needed.

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

1. **Version bump.** Update `version` in `package.json` (semver). Update the README check
   count / flags if user-facing behaviour changed.
2. **Green locally.**
   ```bash
   pnpm install --frozen-lockfile
   pnpm run build      # clean tsc
   pnpm test           # all suites incl. read-only invariant
   pnpm audit --prod --audit-level high
   ```
3. **Commit & push** the version bump; open a PR; let CI + CodeQL go green; merge.
4. **Tag & GitHub Release.** Create a release whose tag matches the version (e.g.
   `v1.7.0`). Publishing the release triggers `publish.yml`, which:
   - re-runs build + tests,
   - `npm publish --provenance --access public`,
   - generates `sbom.cyclonedx.json` and attaches it to the release.
5. **Verify the published artifact.**
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
- **If a scan goes red:** CodeQL findings appear under **Security → Code scanning**;
  Scorecard details are in the public viewer. Treat a failing **read-only invariant** test
  as a release blocker — it means a write path was introduced (see
  `test/unit/api/readonly-invariant.test.ts`; the intended escape hatch is a reviewed
  `// readonly-invariant:allow` line comment, used only for genuine false positives).

## The credibility signals at a glance

| Signal | Where | Proves |
| ------ | ----- | ------ |
| Read-only invariant | `test/unit/api/readonly-invariant.test.ts` (CI) | The tool cannot write to a target org |
| npm provenance | `publish.yml` → npm page | Installed bytes = this public commit |
| CodeQL | `codeql.yml` → Security tab | No known SAST-detectable vulns |
| OpenSSF Scorecard | `scorecard.yml` → public dashboard | Healthy supply-chain practices |
| Dependency audit | `ci.yml` + Dependabot | No known-vulnerable dependencies |
| SBOM | `publish.yml` → release asset | Full dependency inventory per release |
