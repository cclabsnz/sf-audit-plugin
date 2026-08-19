# Roadmap

What is planned for `@cclabsnz/sf-audit` over the next year, and what is deliberately not.

This is a direction of travel, not a commitment with dates. It is maintained by one person
alongside consulting work, so sequence is more reliable than schedule. Current version: 1.8.x.

Anything already shipped lives in [CHANGELOG.md](../CHANGELOG.md).

## Near term

**Finish the test coverage sweep.** 36 of the 88 checks still have no unit test file. The
statement-coverage figure (80%) is now adequate, but that is a side effect rather than the point:
every check corrected for reporting a conclusion it had not established was found by writing a test,
never by reading the code. The remaining 36 are unexamined claims.

**Complete the reporting-accuracy audit.** A sweep for checks that can reach a pass after a silently
caught query failure flagged 17 candidates. Five were confirmed and fixed; the heuristic over-reports
and the rest need reading individually. Until that is finished, some checks may still conflate "we
checked and it is fine" with "we could not check".

**Branch coverage.** Currently 68%. Statement coverage says a line ran; branch coverage says the
decision was exercised in both directions. For a tool whose output is threshold decisions, the
second number matters more.

## Medium term

**Verify the remaining compliance catalogs.** All 119 controls across ten frameworks are currently
source-verified, but framework versions move. The HIPAA catalog pins the operative 2013 Omnibus
rule; the HHS NPRM of January 2025 would delete the Required/Addressable distinction and mandate
encryption, MFA and segmentation. When it finalises, that catalog needs re-pinning and re-verifying
rather than amending in place.

**Deepen Agentforce coverage.** The six AI/agent checks and two named chains cover inventory,
run-as privilege, action surface, channel exposure and monitoring. Channel reachability is the weak
spot: Salesforce does not always expose an agent-to-channel binding in queryable metadata, so some
exposure is reported as unconfirmed rather than asserted. Better binding resolution would turn
inference into fact.

**Experience Cloud CSP and Lightning Web Security.** Currently advisory-only, because the per-site
CSP level lives inside the site's `ExperienceBundle` rather than a `metadata.read`-able type. A real
detection needs retrieve-and-parse, which is a larger capability than the current read clients.

**Sharpen portal Apex analysis.** `apex-rest-endpoint` treats every `@RestResource` running
`without sharing` alike, whether or not it verifies its caller. Distinguishing them would cut false
positives on endpoints that do check.

## Longer term / under consideration

- **Trend analysis across archived runs** beyond the current two-run diff
- **Custom object coverage** in checks currently scoped to standard objects
- **A second maintainer.** The project has a bus factor of one, which is its principal governance
  weakness and the reason gold-level OpenSSF certification is out of reach. See
  [GOVERNANCE.md](GOVERNANCE.md)

## Not planned

Stating these saves everyone time:

- **Any write capability.** No remediation-applying mode, no "fix it for me". The read-only
  guarantee is the product, and it is enforced in CI
- **Telemetry of any kind.** Including anonymous usage statistics
- **A hosted or SaaS version.** The tool runs on the operator's machine against their own org
- **AI-generated findings.** Findings map to specific queried data and cited controls; a model's
  opinion is not evidence
- **Penetration testing features.** No exploitation, no privilege escalation, no runtime probing

## Influencing this

Open an issue. Priority goes to correctness problems — a check that reports something it cannot
support outranks any new feature here.
