# Assurance case

An assurance case states a claim, gives the argument for it, and points at evidence a reader can
check without taking anything on trust. This one exists because `@cclabsnz/sf-audit` authenticates
against production Salesforce orgs, which is a lot to ask of a tool you did not write.

Every piece of evidence below is either a test that runs in CI on every push, a file in this
repository, or a public artefact of a release. Nothing here rests on a promise.

**Top-level claim.** Running `sf audit security` against a production org cannot modify that org,
cannot send its data anywhere other than back to the operator's own machine, and produces findings
that are supported by data actually read from the org.

The case is deliberately narrow. [What this case does not claim](#what-this-case-does-not-claim) is
as important as what it does.

---

## C1. The tool cannot modify the target org

**Argument.** Every org interaction funnels through four client implementations in
`@cclabsnz/sf-core` (`SoqlClientImpl`, `ToolingClientImpl`, `RestClientImpl`, `MetadataClientImpl`),
wired in exactly one place — `src/lib/wire.ts`. Checks receive them only via `AuditContext` and have
no other route to the org. A static scan then asserts that no mutation call exists anywhere in the
source, so the property is enforced rather than reviewed.

**Evidence.** `test/unit/invariants/readonly-invariant.test.ts` fails the build on any of seven
mutation patterns:

| Rule | What it catches |
|---|---|
| HTTP write verb | `method: 'POST' \| 'PUT' \| 'PATCH' \| 'DELETE'` |
| jsforce SObject write | `.sobject(...).create/update/insert/upsert/destroy/delete` |
| jsforce connection write | `conn.create/update/insert/upsert/destroy/delete` |
| Metadata API write | `.metadata.create/update/upsert/delete/rename/deploy` |
| Tooling API write | `.tooling.create/update/upsert/destroy/delete` |
| Bulk API job | `.bulk` / `.bulk2` |
| Composite write graph | `.compositeGraph` / `.createBatch` / `.createJob` |

The same file asserts no direct `fetch()` anywhere in `src/`, closing the bypass of calling the org
outside the clients.

**Counter-evidence handled.** A scan that matched nothing would pass silently and prove nothing, so
the suite first asserts it collected more than 100 source files. Suppressing a rule requires an
explicit `// invariant:allow` comment on the line, which is visible in review rather than silent.

`build-test` is a required status check on `main`, so a violating commit cannot merge.

---

## C2. The tool cannot exfiltrate what it reads

**Argument.** The only network destination is the org the operator authenticated against. Reports
are written to local disk and are fully self-contained, because an audit report carries sensitive
findings and is routinely opened offline or on a locked-down analyst machine — one that fetches a
font or a script from a third party leaks the fact and timing of the review at minimum.

**Evidence.** `test/unit/invariants/network-egress.test.ts` fails the build on five patterns:
remote assets in generated HTML (`<script src>`, `<link href>`, `@import url(https:)`), third-party
HTTP clients (`axios`, `got`, `node-fetch`, `undici`, `superagent`, `request`, `phin`, `ky`), the
raw `node:http`/`node:https` modules, known telemetry/analytics/LLM endpoints (OpenAI, Anthropic,
Google, Sentry, Segment, PostHog, Mixpanel, Google Analytics, Amplitude), and websocket clients.

This is why Chart.js is a real dependency resolved from disk and inlined, and why report fonts are
embedded as data URIs rather than linked.

**The one exception, declared.** `--resolve-domains` makes outbound DNS queries from the operator's
machine to test whether CSP trusted domains still resolve. It is off by default, documented in the
README flag table, and named in the finding it produces. A default run contacts only the target org.

You can run both guards yourself:

```bash
npm test test/unit/invariants
```

---

## C3. It runs with least privilege

**Argument.** The tool requires read access, not administrative access, and specifically does not
require `View All Data`. Where a check cannot read something, it reports that rather than escalating.

**Evidence.** [PERMISSIONS.md](../PERMISSIONS.md) states the minimum permission set, what each
permission is for, and what the tool explicitly does not need. A deployable permission set ships at
[`docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml`](permissionset/SF_Audit_ReadOnly.permissionset-meta.xml).

---

## C4. Findings are supported by data actually read

**Argument.** This is the claim most security tooling gets wrong, and the failure is invisible: a
check whose query fails reports "no problem found", and the report reads as a clean bill of health
for an analysis that never ran. The inverse — asserting a finding from data that was never read —
is equally wrong and equally invisible.

The rule is that a check may report a **pass** only where it completed its analysis, a **finding**
only where the data supports it, and otherwise must report **`inconclusive`**, naming what it could
not evaluate.

**Evidence.** `CheckEngine` converts permission errors into `inconclusive` findings rather than
crashing the run. Scoring treats inconclusive findings distinctly from passes. Five checks were
found violating this rule and corrected, in both directions:

| Check | Was |
|---|---|
| `field-level-security` | Reported "appear appropriately restricted" as a pass in three states where it analysed nothing |
| `public-group-sharing` | Reported "no records shared to All Internal Users" with every share table unreadable |
| `failed-login-detection` | Reported "no brute-force patterns detected" when the per-account breakdown was unavailable |
| `ip-restrictions` | Reported every admin as unrestricted when the IP-range query failed, and certified connected apps it never read |
| `data-classification` | Reported "Shield not detected" when the `EncryptionKey` query had failed |

Each now reports what it could not establish, and each behaviour is pinned by tests. Where partial
data exists the claim is scoped rather than dropped — `public-group-sharing` states which share
tables it checked and which it could not, because an object may be absent by org edition rather
than by permission.

**Coverage of the argument.** 88 checks, 110 test suites, 1008 tests, 80.1% statement coverage.
Coverage is not itself an assurance argument, but an untested check is an unexamined claim, and
every defect listed above was found by writing a test rather than by reading the code.

---

## C5. What you install is what was built from public source

**Argument.** Provenance is verifiable rather than asserted, so a compromised publish is detectable
by the person installing.

**Evidence.** Releases publish from GitHub Actions via npm Trusted Publishing (OIDC) with build
provenance — no long-lived token exists to steal. The npm page shows a signed attestation linking
the tarball to the exact public commit. Verify it directly:

```bash
npm audit signatures
```

Each release also ships a CycloneDX SBOM. The publish job installs its pinned npm with
`--ignore-scripts` and asserts the resulting version, so a lifecycle script cannot execute beside
the credential that can publish this package.

---

## C6. The tool's own supply chain is controlled

**Argument.** A read-only audit tool with a compromised dependency is still a compromised tool.

**Evidence.** All GitHub Actions are pinned to commit SHAs. Dependabot, `pnpm audit` and a PR
dependency-review gate (vulnerabilities *and* a copyleft-licence policy) run on every change. CodeQL
(`security-extended`, over source **and** the CI workflows) and Semgrep (OWASP Top 10 +
security-audit) run on every push and weekly. GitHub secret scanning with push protection is
enabled, and a `guard-internal-files` workflow fails CI if any secret-shaped or internal file is
ever tracked. The `overrides` block in `package.json` pins transitive dependencies with known
advisories.

---

## What this case does not claim

A case that claims everything establishes nothing. Explicitly out of scope:

- **It is not a penetration test.** No vulnerability is exploited, no privilege escalation attempted,
  no runtime behaviour probed. This is a point-in-time configuration review.
- **Findings are not exhaustive.** Absence of a finding is not proof of absence of a problem. Several
  checks are advisory because the underlying setting is not exposed to the read APIs available.
- **A grade is not a certification.** The A–F grade and health score are prioritisation aids. They do
  not represent compliance with, or accreditation under, any standard.
- **Compliance mappings indicate relevance, not conformance.** A control rendering "No findings
  detected" means this audit surfaced nothing mapped to it, which is not an attestation.
- **The invariants are static.** They scan this package's source. They do not prove the Salesforce
  SDK beneath them is read-only, only that this package never asks it to write.
- **Results are point-in-time.** Configuration drift can invalidate any finding at any moment.
- **One maintainer.** There is no second reviewer on changes. See
  [GOVERNANCE.md](GOVERNANCE.md) for what that means and how it is mitigated.

---

## Reviewing this case

The argument is only as good as its evidence, and all of it is executable:

```bash
npm test test/unit/invariants   # C1 and C2, the enforced invariants
npm test                        # the whole suite, including the drift guards
npm audit signatures            # C5, published provenance
```

If you find a gap in this argument, please open an issue or use the private reporting process in
[SECURITY.md](../SECURITY.md). A hole in the assurance case is a security finding.
