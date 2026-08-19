# Governance

How decisions get made on `@cclabsnz/sf-audit`, who makes them, and what happens if that person is
unavailable.

This document describes the project as it actually is — a single-maintainer open source project
backed by a consultancy — rather than a committee structure that does not exist. Where that is a
weakness, it says so.

## Project model

**Benevolent-maintainer.** The project is maintained by CloudCounsel Limited (Auckland, New
Zealand), which also uses it in client engagements. Decisions are made by the maintainer, in the
open, on public issues and pull requests.

There is no foundation, steering committee, or voting process, and inventing one would misrepresent
how the project runs. What is real: every change lands through a public pull request against
`main`, with the CI gates below, and the reasoning is recorded in the commit message and PR.

## Roles and responsibilities

| Role | Held by | Responsibilities |
|---|---|---|
| **Maintainer** | Gaurav Thakur (CloudCounsel Limited) | Accepts or declines changes; owns releases; triages issues and vulnerability reports; owns the npm package, GitHub repository and the OpenSSF Best Practices entry |
| **Security contact** | Same, via [SECURITY.md](../SECURITY.md) | Receives private vulnerability reports; acknowledges within 5 business days; coordinates disclosure |
| **Release manager** | Same, per [RELEASE.md](RELEASE.md) | Cuts releases; releases publish only from a published GitHub Release, never automatically on merge |
| **Contributors** | Anyone | Propose changes by pull request under [CONTRIBUTING.md](../CONTRIBUTING.md) |

The maintainer role is currently one person. That is the project's principal governance weakness and
is treated as such below rather than glossed over.

## How changes are accepted

1. Work happens on a branch and lands via pull request. `main` is protected: no direct pushes, no
   force pushes, linear history required, and `enforce_admins` is on, so the maintainer is subject
   to the same gates as anyone else.
2. Seven status checks must pass: build and tests, `pnpm audit`, dependency review, CodeQL for
   source, CodeQL for workflows, Semgrep, and the internal-files guard.
3. The [testing policy](../CONTRIBUTING.md#testing-policy) requires tests with any behavioural
   change; the drift guards require documentation to stay in step with the code.
4. Changes touching the read-only or network-egress invariants are held to the argument in
   [ASSURANCE-CASE.md](ASSURANCE-CASE.md). Weakening an invariant requires the case to be updated in
   the same change.

**What is missing:** a second person reviewing changes before merge. With one maintainer, no
pull request receives independent review, and the automated gates are doing work that a reviewer
would otherwise do. This is stated plainly in the assurance case as a limitation.

## Decision-making

- **Routine changes** — bug fixes, new checks, dependency updates: maintainer's discretion, in the
  open.
- **Behavioural changes to findings** — anything that alters a severity, a threshold, or whether a
  check reports a pass: recorded in the commit message with the reasoning, because these change
  customers' health scores. Recent examples are the five checks corrected for reporting conclusions
  they had not established.
- **Breaking changes** — flags, output formats, check ids: a major version bump and a changelog
  entry describing the migration.
- **Disagreement**: raise an issue. The maintainer decides, and says why in writing.

## Continuity if the maintainer is unavailable

Honest position: the project has a **bus factor of one**. If the maintainer were unavailable
indefinitely, no one else could currently publish a release. The following limits the damage rather
than eliminating it.

**What survives regardless.** The source is Apache-2.0 on GitHub, so anyone can fork and continue.
Released versions stay installable from npm independent of the maintainer. Every release carries
signed provenance and an SBOM, so a fork can verify what it inherited. No part of the tool phones
home or depends on infrastructure the maintainer runs — an installed copy keeps working with no
server behind it.

**Access and recovery.** The repository is owned by the `cclabsnz` GitHub organisation, not a
personal account, so ownership can be transferred without needing the maintainer's personal account.
npm publishing uses Trusted Publishing (OIDC) bound to the repository and workflow rather than a
personal token, so publishing rights follow repository control. CloudCounsel Limited holds the
organisation credentials.

**What would still be lost.** Ongoing maintenance, vulnerability response, and the accumulated
judgement in the compliance catalogs and attack-chain model. A fork inherits the code and the tests,
not the maintainer.

**Improving this** requires a second maintainer with commit and release rights. That is a
people problem, not an engineering one, and it is the reason the project targets the OpenSSF
Best Practices **passing** badge rather than gold — gold requires two unassociated significant
contributors, two-person review, and a bus factor of two or more.

## Code of conduct

[CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) applies to all project spaces. The maintainer is the
enforcement contact.

## Changing this document

By pull request, like anything else.
