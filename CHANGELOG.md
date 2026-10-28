# Changelog

All notable changes to `@cclabsnz/sf-audit` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry mirrors the [GitHub Release](https://github.com/cclabsnz/sf-audit-plugin/releases) for that tag, which is the canonical
published note and carries the signed provenance attestation and CycloneDX SBOM for the build.

## [Unreleased]

### Changed

- **Active debug traces no longer count as an exposed secret.** The finding fires on a trace at any log level, and only View All Data users can read debug logs, so it grants no attacker capability. It no longer feeds `cred-theft-pivot`, nor the potential chain from an unauthenticated foothold to credential theft.
- **Org-wide email spoofing no longer grants egress.** An address open to all profiles, or mail without DKIM, is a phishing surface rather than a channel for moving data.

### Fixed

- **`cred-theft-pivot` needs an egress path among its steps.** It checked only that some finding granted egress, so exposed secrets plus a finding outside the chain (org-wide email spoofing, a session id in an outbound message) fired a CRITICAL chain with no egress step in it.

## [v1.20.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.20.0) — 2026-10-28

Findings now say which threats they enable, and each named attack chain says who would run it and
which single fix stops it.

### Added

- **STRIDE and LINDDUN on every finding.** Each check is mapped to the STRIDE categories it guards (all 109 checks) and, where personal data is involved, to LINDDUN privacy categories (32 checks). Findings carry them as `threats` in JSON, as a **Threats:** line in Markdown, and as `stride:` / `linddun:` rule tags in SARIF. Tagging never changes severity, score or grade.
- **Threat view in the Markdown report.** One row per category, reading "N findings (from N checks)", "no findings from N checks", "not assessed in this run" or "not assessed by this tool". An empty category is never shown as assurance, and privacy and security readings of the same finding are kept apart, not netted against each other.
- **Named attack chains are abuse cases.** Every named chain states its actor, goal and preconditions, and its break point: the fix that stops the chain in every case it fires. Markdown, HTML and the executive report show "Abuse case:" and "Breaks the chain:", with the full remediation below it. SARIF chain results carry `abuseCase`, and break-point steps carry `breaksChain`.

### Changed

- **The attack-chain diagram marks the proven break point** ("✂ BREAK POINT", on every step of a multi-step break point) instead of guessing one cut-point. Steps whose capability was inferred no longer show a capability label.
- Potential chains label their fix text "Recommended fixes" in Markdown, HTML and the executive report, since no single break point is proven for them.
- **`cred-theft-pivot` needs an exposed secret.** The chain now fires only when one of its steps exposes a credential (including credentials stored in custom settings), so orgs without one no longer show it.
- **Moves to `@cclabsnz/sf-core` 0.12.** `queryAll` now reads every page instead of stopping at the client's row limit, so reads that came back short on large orgs are complete.

### Fixed

- **The executive report's "Breaks the chain" line no longer shows the full remediation list.** It now names the break point; the full list follows as "Full remediation".
- **An expired session stops `incident collect` again.** sf-core 0.12 reports a failed log download as `INVALID_SESSION_ID` instead of "HTTP 401", so collect recorded every remaining log as failed instead of stopping. Error classifiers now read the error's code and status, not only its message.
- A Salesforce error that arrives with only a code (`INSUFFICIENT_ACCESS`, or `ERROR_HTTP_403` with no body) is classified as a permission problem in `incident collect` and the API log listing, and `ERROR_HTTP_404` counts as a missing object in the checks that probe for optional features.
- **A malformed agent query no longer reads as "Agentforce not enabled".** The AI & Agents checks counted `MALFORMED_QUERY` as an absent object, which became reachable with sf-core 0.12; they now share the missing-object test the other checks use, so a broken query is inconclusive.
- A failed download whose error body is empty now names its code and status (`ERROR_HTTP_403 HTTP 403`) in `incident collect` and the API log listing, instead of an empty reason.
- `users-and-admins` no longer advises raising `org-max-query-limit`, which no longer limits the read. When the assignment count differs from the rows read, it advises re-running the audit.

### Security

- `fast-uri` pinned to 3.1.9 or later, closing Dependabot alerts #44–47. (#181)

## [v1.19.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.19.0) — 2026-10-23

When the audit user cannot see who holds Modify All Data or View All Data, the report now says so
instead of reporting it as passed.

### Fixed

- **"0 user(s) have View All / Modify All Data" is no longer reported as passed.** Every org with an active System Administrator has holders of both, so zero means the audit user could not see the assignments. The findings now read "Could not confirm who holds …" and are inconclusive, with advice on what to re-run as.
- `users-and-admins` reads every batch of permission set assignments, and checks the read against a `COUNT()` of the same query. When the client's row limit (default 10,000, or `org-max-query-limit`) cuts the read short:
  - counts are reported as lower bounds ("At least 8 user(s) …") at that bound's severity, and are never reported as passed;
  - a zero is inconclusive;
  - a new inconclusive finding, `users-and-admins-read-incomplete`, says how much was read. Counts under a reporting threshold may not appear at all, and this finding is the signal.
  
  A failed `COUNT()` is treated the same way and no longer fails the check.
- An unknown or lower-bound Modify All / View All count is shown as "unknown" on the HTML dashboard, not a number, and the history diff does not compare it, including an archived "0 user(s)" from earlier versions. JSON output still carries 0 for these metrics.

### Changed

These follow from treating an unreadable count as unknown. They affect runs where the audit user cannot see permission set assignments, or where there are more assignments than the row limit:

- The health score drops. A passed finding counts towards the maximum score and an inconclusive one does not, so losing the two passes makes the open findings weigh more.
- `--fail-on-inconclusive` now exits 3.
- `users-and-admins` counts as not assessed in evidence coverage, which can cap the grade at B.
- In SARIF, `executionSuccessful` is false and the findings are listed under `toolExecutionNotifications`.
- `audit diff` shows the move from passed to inconclusive as a severity change.

### Dependencies

- **@oclif/core** 4 → 5.1.8, **@salesforce/sf-plugins-core** 13.0.0 → 13.0.7,
  **@salesforce/core** 9.3.0 → 9.4.0, **zod** 4.4.3 → 4.6.7. No change to commands or flags. (#170)
- Pinned actions: codeql-action v4.39.0, scorecard-action v2.5.0, upload-artifact v7.0.2.
  (#168, #169, #171, #174)

## [v1.18.1](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.18.1) — 2026-10-22

The HTML report's dashboard now agrees with the score and the executive report.

### Fixed

- The HTML report's dashboard counted passed and inconclusive findings, so it showed 66 LOW where
  the executive report showed 2. The donut and severity cards now count open findings only, and
  the executive report's severity chips no longer count waived findings.
- The grade reason and coverage note in the HTML report were squeezed into a narrow column beside
  the score gauge. They now sit below it.

### Changed

- Unattended installs use `sf plugins trust allowlist add` (sf CLI 2.135.0 or later) in place of
  the `jq` script.

## [v1.18.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.18.0) — 2026-10-21

Evidence coverage on a live org rises from about 58% to 96–97%, and grades and attack chains now
mean what they say. Found by running the audit against a Developer Edition org and two sandboxes.

### Fixed

- `engines.node` now says `>=22.0.0`, not `>=18.0.0`. `@salesforce/core` 9 and
  `@salesforce/sf-plugins-core` 13 already require Node 22, so the plugin never ran on 18 or 20.
  The README's requirements say Node.js 22+ to match.
- About 40 checks sent queries the org rejected, then reported "insufficient permissions":
  - fields that do not exist (`LoginHistory.Username`, `ContentDistribution.PasswordEnabled`,
    `Organization.MyDomain`, `RestrictionRule.Active`, the wrong MFA permission field, and others)
  - objects sent to the wrong API (`TraceFlag`, `DelegateGroup`, `ExternalCredential`,
    `NetworkAccess` and `CorsWhitelistEntry`)
  - filters on fields Salesforce will not filter (`SetupAuditTrail.Section`, `LoginHistory.Status`)
  - invalid syntax: the reserved alias `expr0`, and `COUNT(Id)` on `FieldDefinition`
- Commands pinned API 62.0 and could not see newer fields. They now use the org's own version.
- A rejected query is reported as "query rejected by the org" and quotes Salesforce's error.
  "Insufficient permissions" is kept for real access errors, and it names the needed permission.
- Permission fields that only some editions carry are checked by describe before they are queried.
  If one is absent, the check says the feature is not available in this org; that never counts as
  a pass.
- `MALFORMED_QUERY` was treated as "object not present", so a broken query read as clean.
- Inconclusive checks no longer raise the health score.

### Changed

- Every output gives the reason for the grade, for example `F: 2 CRITICAL findings (D allows none)`.
- Only open findings and named attack chains count towards the grade. Potential chains do not.
- CRITICAL is kept for breach-grade exposure:
  - The super-admin finding and Modify All Data are rated by how many hold them (more than 5 is
    CRITICAL, more than 3 is HIGH).
  - Modify All Data and separation-of-duties leave out users the super-admin finding already
    covers, so the same admins are not counted three times.
  - In a sandbox, admin-count findings are capped at HIGH.
  - An expiring certificate is HIGH.
  - Externally callable Apex is CRITICAL only when a class declares `without sharing`.
- "Unauthenticated bulk exfiltration" needs a confirmed guest exposure. "Standard user to org
  takeover" needs a low-trust way in and an escalation a non-admin can use. A guest user merely
  existing no longer opens either chain, or any potential chain.
- The remediation roadmap lists only work: INFO inventories and checks that gathered no evidence
  are left out. Healthy lowest-band results (few failed logins, a Health Check score of 85 or
  more, a small number of View/Modify All Data holders) are reported as passed.
- Reports with unassessed checks point to `sf audit preflight` and PERMISSIONS.md.
  `PERMISSIONS.md` and the read-only permission set now ship in the npm package.

### Added

- `scripts/capture-schema.mjs` and a captured Developer Edition schema
  (`test/fixtures/schema/developer-edition.json`, standard fields only). A test runs every
  check against it and fails on any query the org would reject.
||||||| a23c86e

## [v1.17.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.17.0) — 2026-10-17

109 checks (up from 95) and 19 attack chains (up from 17).

### Added

- Fourteen checks for surfaces the audit did not reach before:
  - `genai-prompt-template-grounding`: active Prompt Templates grounded on system-mode flows or
    unshared Apex, or mixing untrusted external fields with sensitive CRM data.
  - `data-cloud-data-space-isolation`: a default Data Space shared with integrations, partner or
    agent users, and unconstrained Data Share Targets.
  - `platform-event-subscriber-context`: Platform Event subscribers running in system context or
    as an admin while low-trust or guest users can publish the event.
  - `flow-http-callout-credential-bypass`: Flow HTTP callouts with embedded tokens, or that go
    around Named Credentials.
  - `oauth-device-and-asset-token-flows`: the OAuth Device Flow and Username-Password Flow
    enabled in OAuth and OpenID Connect Settings. An unreadable setting is an advisory, never
    "disabled".
  - `delegated-authentication-exposure`: Delegated Authentication over unencrypted or non-mTLS
    endpoints, or assigned to System Administrator profiles.
  - `delegated-administration-groups`: delegated admin groups that can manage users, log in as
    them or assign permission sets, which permission set queries do not show.
  - `auth-provider-registration-handler`: a RegistrationHandler running as an admin that links
    accounts by email, open to pre-auth account takeover.
  - `inbound-email-handler-exposure`: email services that accept any sender and run Apex.
  - `org-wide-email-spoofing`: Org-Wide Email Addresses open to all profiles without SPF/DKIM
    alignment.
  - `external-account-hierarchy-exposure`: Partner Super Users and External Account Hierarchies
    that widen portal record reach past the external OWD.
  - `restriction-rules-integrity`: inactive Restriction Rules leaving records exposed, and
    conflicting active rules on one object.
  - `package-post-install-supply-chain`: packaged Apex implementing `InstallHandler`, which runs
    in system context on every install and push upgrade.
  - `shield-tenant-secret-lifecycle`: Shield tenant secrets not rotated in 365 days.
- Two attack chains, both CRITICAL: **Unauthenticated inbound email to privileged code
  execution** (`inbound-email-rce`) and **Guest or low-trust platform event publish to automated
  process escalation** (`platform-event-priv-esc`).
- Every report states its evidence coverage: the share of checks that gathered evidence, and the
  ids of those that could not. Below 90% a would-be A is capped at B, and the report says why.
  `grade` stays a plain A–F letter; the detail is in the new `coverage` field of the JSON output.
- Accepted-risk waivers (`--waivers`, or `.sfaudit-waivers.json` in the working directory). A
  waived finding leaves the score, `--fail-on` and the executive priorities and roadmap, and is
  listed under Accepted Risks. Matching is exact, waivers run at most 365 days, and a CRITICAL
  finding needs `acknowledgeCritical`. The loaded file's path is always printed.
- `sf audit security --no-history` skips the automatic archive to `~/.sf/audit-history`, and the
  archive is now skipped by default in CI (`CI` set to a truthy value, `GITHUB_ACTIONS`, `TF_BUILD`
  or `JENKINS_URL`), so ephemeral or shared runners don't keep org data. `--keep-history` archives
  anyway and wins over `--no-history`.
- `sf audit security --format sarif` writes a SARIF 2.1.0 log for GitHub code scanning. Results
  carry stable fingerprints so a recurring finding keeps one alert, the tool version comes from
  the package, and checks that could not gather evidence are reported as tool notifications
  rather than alerts.
- Attack chains now render as a diagram: each step is a card (severity, finding, capability
  granted) joined by arrows, with the step whose fix breaks the chain marked as the cut-point.
  It appears in the attack-path cards of the HTML report (dark) and in the Attack Scenarios of
  the executive report (light). The diagram is self-contained inline SVG, so it works under the
  executive report's no-script CSP and prints to PDF; long chains wrap onto rows of four.
- `sf audit apps --emit-permset <dir>` writes each app's suggested least-privilege permission set as
  a local `.permissionset-meta.xml` for review. Nothing is deployed. Apps whose recommendation is
  held back (soak window, many interactive users, incomplete logs) get no file, and generated names
  are unique, valid metadata API names.
- `sf audit apps` now reads `BulkApi2`, `GraphQlQueryExecution` and `AuraRequest` logs as well as
  `RestApi`, resolves External Client Apps, and counts profile object permissions as granted access.

### Changed

- Apex findings now say which control is bypassed. `WITH SYSTEM_MODE` and
  `AccessLevel.SYSTEM_MODE` switch off CRUD/FLS, not record sharing, so they are reported as
  `apex-crud-fls-system-mode` (MEDIUM) and, for guest-callable classes, as the new
  `guest-executable-apex-system-mode` (HIGH), never as a CRITICAL sharing bypass. `USER_MODE`
  counts as CRUD/FLS enforcement.
- A guest-callable class that calls a helper declared `without sharing` is now CRITICAL
  `guest-executable-apex-unprotected`, naming the helper. A guest-callable `inherited sharing`
  class is no longer reported CRITICAL: at an entry point it runs with sharing.
- `@RestResource` classes without sharing are reported alongside `@AuraEnabled` and
  `@RemoteAction` ones.
- A class's sharing keyword is read from its own declaration, ignoring comments, so a
  `without sharing` class mentioning "with sharing" in a comment is no longer read as protected.
- `salesbleed-pattern` also fires when the way out is a CSP Trusted URL whose domain is parked
  or no longer resolves: whoever registers it receives anything an agent puts in a link or image.
  When the org shows where outsider text enters (an open email handler, guest write access), that
  finding leads the chain as evidence.
- `--scoring-config` is now checked strictly. An unknown or misspelled key (`gradeTresholds`,
  `minscore`) is an error instead of being silently ignored, `minScore` must be 0–100, and grade
  thresholds must be ordered after merging with the defaults (A at least as strict as B, and so
  on). Errors name the offending path. A JSON Schema for editors ships as
  `schemas/scoring-config.schema.json`, and `config/scoring.sample.json` now lists every
  registered check.
- The npm description states the current check count, and a test keeps it in step.
- README documents unattended CI installs and how to check a release's provenance.
- Requires `@cclabsnz/sf-core` 0.11.0.

### Fixed

- Several of the fourteen new checks could not see their evidence, and some reported a pass
  when their query failed; their tests passed because the mocks returned fields the real queries
  never selected. They now read what the org actually returns, and a failed read is inconclusive,
  never a pass.
- `genai-prompt-template-grounding` no longer builds a regular expression from a class name the
  org returns; the declaration is found with literal patterns in one linear pass.
- `sf audit apps` no longer reports an empty, clean-looking result when `EventLogFile` cannot be
  read: a failed listing is an error, and partly failed downloads mark the output incomplete and
  suppress revoke recommendations.
- `connected-apps` lists External Client Apps for manual review of their OAuth policies. Their
  policies are not evaluated automatically, so no External Client App is reported as
  unrestricted or as passing. A failure to list them is reported as inconclusive, and the
  connected-app results still stand.

### Security

- Local stores that hold org data (`~/.sf/audit-history`, incident bundles, evidence CSVs,
  guest-log staging) are now created owner-only: directories 0700, files 0600, through
  `secureFs` from `@cclabsnz/sf-core`. An existing history root is tightened on first use.
  Report files written to a user-chosen `--output` directory keep that directory's permissions.
- Every HTML report now carries a Content-Security-Policy that forbids all network requests:
  the executive report allows no script at all, and the interactive reports allow inline script
  only. Values in the history report that are read back from disk (grade, score, dates) are
  escaped or coerced, so a tampered history file cannot inject markup or script.

## [v1.16.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.16.0) — 2026-10-09

The AI & Agents checks now run on real orgs: since 1.6.0 they had been silent everywhere, because the agent inventory asked the Tooling API for objects only the data API serves. This release fixes that, and adds two checks and a named chain for the SalesBleed and PipeLeak pattern, all verified against a live Agentforce agent.

### Added

- `agent-query-reach` (AI & Agents): flags agents carrying the standard General CRM topic or a
  Query Records action, the open-ended query SalesBleed used to read Account data from a poisoned lead.
- `agent-outbound-actions` (AI & Agents): flags Slack, email, external-service and MCP actions that
  send data out of the org without user confirmation (HIGH), and standard Slack/email actions whose
  confirmation setting is not readable (MEDIUM).
- `salesbleed-pattern` named attack chain (HIGH): open-ended query reach plus an unconfirmed outbound action.

### Fixed

- **AI & Agents checks never ran on a real org.** `agent-inventory` read `BotDefinition` and
  `BotVersion` through the Tooling API, which answers `INVALID_TYPE` for both even in orgs with
  active agents, so every org was classed as "Agentforce not enabled" and all AI & Agents checks
  stayed silent since 1.6.0. Both are now read through SOQL. Verified against a live agent;
  `test/fixtures/agentforce/live-agent-v67.json` replays it so the shape cannot regress.
- Agent checks now follow the platform's real shapes: one planner per agent version (only the
  active version is reported), topic and action links that hold record Ids rather than names, and
  Flow actions judged by what the active flow version does (Send Email, email alerts, external
  services).

## [v1.15.1](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.15.1) — 2026-10-06

The executive and incident reports now say which tool produced them. No change to any check, flag or finding.

### Changed

- **The executive and incident reports now credit the tool.** One line at the end, "Prepared with
  sf-audit, an open-source, read-only Salesforce security tool", matching the credit the technical
  reports already carry. The link is tagged with the report type only (`executive-report` or
  `incident-report`) and never the org or client. It is a plain hyperlink, so opening a report
  still fetches nothing.

## [v1.15.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.15.0) — 2026-10-06

One new check, and four existing checks that stop reporting conclusions they had not established.

### Added

- **`lightning-message-channel`** flags Lightning Message Service channels with `isExposed=true`,
  which outside namespaces, including every installed managed package, can publish to and
  subscribe on. Sharing rules, org-wide defaults and field-level security do not reach the bus.
  Salesforce's AppExchange Security Review requires `isExposed=false`, and the setting cannot be
  reversed once true, so remediation is a new channel plus migrating its publishers and
  subscribers, not a toggle. Installed channels are reported separately at LOW, since the fix sits
  with the vendor. The finding says what the metadata cannot show: what a channel carries is
  visible only in the publishing component. One Tooling query; grants no attack-chain capability.
  Check count is now **93**.

### Fixed

- **Four checks no longer report conclusions they had not established.** Each was both untested and
  held a `catch` that swallowed a query failure; writing the tests is what surfaced the defects, as
  it has every previous time.

  - **`mfa-enforcement` asserted a HIGH finding on a failed query.** When
    `PermissionsMultiFactorForUiLogins` could not be read - the field is absent in some editions -
    the empty result was treated as "nobody has MFA enforced", so every external user fell into the
    shortfall bucket and the check named them, at HIGH, as lacking MFA. Over-reporting was not the
    safe direction: it produced a remediation task against real users and an SBS-AUTH-004 claim on
    no evidence. Now inconclusive.
  - **`audit-trail` charged a clean org for being clean.** Zero sensitive-section changes in seven
    days produced an unmarked LOW finding, and `scoring.ts` excludes only passed and inconclusive
    findings from the penalty numerator - so a quiet week cost health score. Now marked passed. Its
    Manage Event Log Files query also failed silently, leaving SBS-MON-002 looking satisfied rather
    than unevaluated; now inconclusive.
  - **`named-credentials` discarded a HIGH finding it had already established.** A failed Apex scan
    returned early, which also threw away the plaintext-HTTP (SBS-INT-003) and anonymous-principal
    findings - both derived purely from the credential records, which had been read successfully.
    The Apex scan only ever informed the unused analysis, so only that is now skipped, and it says
    so. `unusedNamedCredentialsCount` is omitted rather than reported as zero when not computed.
  - **`legacy-api-version` left no trace when RemoteProxy could not be filtered.** The absence of a
    SOAP remote-site finding was indistinguishable from having established there are none. The
    sibling `remote-sites` check is not cover for it: that reports remote sites in general and makes
    no SOAP determination. Now inconclusive.

- **`named-credentials` no longer prints the word "null" into operator advice.** `Endpoint` is
  nullable for External Credential-backed entries. The inventory finding handled that; the unused,
  HTTP and anonymous notes interpolated it directly.

### Security

- Removed `sprintf-js` from the dependency tree (GHSA-hp3w-g68c-fv3c, no patched release). It
  reached the tree only through Jest's coverage loader via `js-yaml` 3; that loader now resolves
  `js-yaml` 4, which does not depend on it. Development-only, and not in the shipped runtime.

### Changed

- npm description corrected from 88 to 93 checks, with keywords for event monitoring, guest-user
  and incident-response searches. The README feature list now includes `sf audit incident`.
- 57 unit tests across those four checks, taking the untested-check count from 33 of 93 to 29 and
  the suite to 151 files / 1519 tests. Branch coverage 75%, statements 84%.

## [v1.14.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.14.0) — 2026-10-06

Two investigation commands for Real-Time Event Monitoring **Guest User Anomaly** alerts, and every
open dependency advisory cleared.

### Added

- **`sf audit incident collect`** (read-only). Discovers anomaly *waves* (adjacent days on one
  site), then for each wave day plus one baseline day either side streams the EventLogFiles, keeps
  only guest-user rows, and snapshots the audit trail, guest configuration and logins from actor
  addresses into a sha256-sealed bundle under `~/.sf/incidents/`. Collection is resumable (intact
  logs are reused), a bundle is refused until it is sealed complete, and only "unavailable" or
  "no permission" errors degrade to a stated gap; anything else stops the run.
- **`sf audit incident report`** (offline). Analyses a bundle and writes an HTML report (prints
  to PDF), Markdown, JSON, and one evidence CSV behind every number cited. `--redact` truncates
  addresses and replaces linked users' names and emails with their ids.
- **The analysis**:
  - spike against baseline, counting controller calls only and never summing across log types;
  - actor blocks, told apart from always-on proxies by their own history and the org's normal
    busiest block;
  - reply sizes via unambiguous AuraRequest/Sites joins, against an empty size learned per action;
  - login outcomes and identity links, with shared egress (proxies, NAT) set aside;
  - guest-access configuration changes between waves, including hardening applied to one site but
    not another.
- **No false reassurance.** "No evidence of access" and "within baseline" are reported only when
  the collected evidence supports them; otherwise a wave reads "not assessed" with the reason, and
  every report states what it cannot tell you.

### Security

- Cleared all open Dependabot advisories: `undici` 8.10.0 → 8.11.2, and `csv-parse` 5 → 7 by
  raising `@salesforce/core` to `^9.3.0`, which carries the fix to installers, not just this repo.
- Raised the `fast-uri@3` override floor to `^3.1.8` and the `brace-expansion` floor to
  `^5.0.11`. `pnpm audit --prod` and a packed consumer-tree `npm audit` both report zero
  vulnerabilities.

### Notes

- Not a security check: the check count stays at 92 and the security grade is unaffected.
- `--ip-ranges` reads provider range files you supply; the plugin never fetches them, so the org
  stays the only network destination.

## [v1.13.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.13.0) — 2026-09-25

Five new attack chains, and the correlation defect that kept them from being expressible.

### Added

- **Five named attack chains**, taking the catalogue from eleven to sixteen:

  - **Standing OAuth access outside every login control** (HIGH) — broad standing API access
    (Full scope, a never-expiring refresh token, or both) combined with something that removes the
    containment or the observation: a token matching no current connected app, a token unused for
    months, or connected apps exempted from login IP enforcement. A refresh token is not a session.
    Login controls engage once at authorisation and never again, and the exchange writes no
    `LoginHistory` row, so this reach is invisible to a check that reads logins.
  - **Self-service registration into an over-shared portal** (HIGH) — a site accepting
    self-registration plus an external sharing model or portal-reachable code that gives any
    account holder more than their own records. Every other chain starting from an authenticated
    external user assumes the attacker already has an account.
  - **Live session ID handed to an external endpoint** (HIGH) — an outbound message configured to
    send the session ID, plus a reason a replayed session would be neither blocked nor recorded.
  - **Org files served to anonymous callers, with no record of what left** (HIGH) — unauthenticated
    file access plus no classification or monitoring. Deliberately asserts no pivot into org data,
    because anonymous file access returns the file and stops.
  - **Visualforce XSS pattern reaching a privileged session** (HIGH) — an unencoded markup pattern,
    weakened browser-side controls, and privileged accounts to target. Asserts a reading order, not
    exploitability: markup cannot show whether an attacker controls the rendered value.

### Fixed

- **Eleven findings now grant the attacker capabilities they always carried.** `ChainEngine`
  correlates on capabilities, so a finding absent from `CapabilityRegistry` could never be a step in
  a named chain and never appeared in the emergent pass either. Forty-seven of the ninety-two checks
  were in that state, and nothing reported it: an absent key is indistinguishable from a deliberate
  decision that the finding grants nothing.

  The eleven: `custom-settings-credentials`, `apex-rest-without-sharing`,
  `apex-crud-fls-without-sharing`, `apex-crud-fls-missing`, `outbound-messages-session-id`,
  `public-content-public-documents`, `public-content-public-static-resources`,
  `content-links-no-expiry`, `content-links-no-password`,
  `experience-cloud-site-self-registration` and `connected-app-full-scope`.

  Two non-grants are deliberate and pinned by tests, since a non-grant is the easiest thing to
  regress by helpfully adding a capability. Content links grant `data-read` but not
  `unauth-foothold`, which would pair them with every bulk-read sink in the emergent pass and assert
  a path between unrelated data. `connected-app-infinite-refresh-token`, `oauth-token-stale` and
  `oauth-token-unmatched-app` grant nothing, because persistence and disuse are evidence about a
  token rather than reach an attacker holds; they earn their place as chain steps instead.

- **`js-yaml` floor is stated rather than inherited from the lockfile**, so a consumer resolving the
  tree independently cannot land on a version the `overrides` block was there to exclude.

### Internal

- The consumer-tree audit now packs the tarball and audits what actually ships, which is
  authoritative when it disagrees with the lockfile audit. The `jszip` MIT election is recorded so
  the licence gate matches the shipped tree.
- The org-data commit guard widened past org ids to User and connected-app ids, `my.salesforce.com`
  hosts, government email addresses and routable IPs, and the `commit-msg` hook was brought into
  step with `pre-commit`.
- `repository.url` normalised so npm stops rewriting it on publish.
- Trust documentation no longer carries a zero-vulnerability claim, which went stale within a day.
- The attack-chain docs stated two different counts: the README feature list and the line above
  the `docs/ATTACK-CHAINS.md` table both said eleven, while the table carried sixteen. The existing
  drift guard asserted one phrasing in one file, which the README narrative satisfied on its own,
  so neither stale count failed. `readme-chain-list.test.ts` now checks every stated count in both
  docs against `NAMED_CHAINS.length` and names the file that disagrees.

## [v1.12.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.12.0) — 2026-09-07

A check that shipped in the source but never ran, now registered, plus tests for three more.

### Added

- **`soap-login-api-auth`** — flags accounts that authenticate with SOAP API `login()` but do not
  hold the "Use Any API Auth" permission that Winter '27 requires, and separately flags holders
  that no longer need it.

  The check class has been present and compiling since Winter '27 planning and **had never run**:
  its registry, compliance, `CheckMeta` and test wiring were deferred behind another unfinished
  check and then forgotten. An unregistered check is invisible to the whole suite, so nothing
  failed. It runs now.

  Worth stating because published coverage of this change routinely gets it wrong: "Use Any API
  Auth" is **not** the same permission as "Use Any API Client", which the separate
  `api-client-permission` check covers. Granting the wrong one leaves the breakage in place while
  feeling remediated. The compliance mapping deliberately does not reuse the Use Any API Client
  control, for the same reason.

  Both halves matter. The missing-permission half is an availability finding: the failure lands at
  authentication, server to server, with no error anywhere in the Salesforce UI. The
  already-granted half is a security finding, because granting broadly at profile level is the
  common response to this change and converts a breakage problem into a standing-privilege one.

### Changed

- Check count is now **92**.

### Internal

- Unit tests added for `connected-apps`, `connected-app-inactivity` and `api-client-permission`.
  Untested checks drop from 36 to 33 of 92. The `connected-apps` tests pin the
  `connectedAppNames` cache write that two other checks read, and the `api-client-permission`
  tests assert on the query text so a copy-paste between the two easily-confused API permissions
  fails a test.

## [v1.11.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.11.0) — 2026-09-07

One new check, closing a blind spot that the SaaS token-theft campaigns of the last year
turn on: a connected app can hold a working key to your org while every existing check
reports it as dormant.

### Added

- **`oauth-token-inventory`** — inventories standing OAuth authorisations from
  `OauthToken`, so you can answer "which apps can act in this org right now, and for how
  many users" without waiting for a login that will never come.

  `connected-app-inactivity` reads `LoginHistory` and calls an app inactive after 90 days
  with no OAuth login. That is the wrong signal for a refresh token: the app presents the
  token, gets an access token back, and no `LoginType 'OAuth%'` row is written for the
  exchange. So an app can be reported as dormant and low risk while still holding a
  working credential. When a vendor is breached, the remediation is to revoke access and
  refresh tokens rather than disable a login, and that requires an inventory nothing in
  this plugin previously produced.

  Emits three findings: an app holding live tokens that is absent from the connected app
  inventory (MEDIUM), tokens unused for 90+ days or with no recorded last use
  (MEDIUM/LOW), and the full per-app inventory (INFO), which is always emitted so the
  report carries the revocation worklist even when nothing is wrong.

  Token material is never selected. `OauthToken` exposes `AccessToken`, `RequestToken` and
  `DeleteToken` as queryable strings, and findings are written to disk, so the exclusion is
  enforced where the query is built rather than by convention, and asserted in the tests.

  Degrades honestly rather than quietly: if `OauthToken` cannot be read the check goes
  inconclusive instead of reporting an org with no standing tokens, and if
  `ConnectedApplication` returns nothing the cross-reference is skipped rather than
  flagging every app as unmatched.

Check count is now **91**.

## [v1.10.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.10.0) — 2026-09-07

Two additions for callers that drive this plugin programmatically: find out what the audit
user can actually see *before* spending a run, and get the result back without paying for
the half of it that is passing checks and prose.

### Added

- **`sf audit preflight`** — reports what this audit user will and will not be able to
  establish, before a run is spent. Reads the caller's effective permissions from
  `UserPermissionAccess` in a single query and names the checks that will return
  inconclusive, with the grants that would fix them. The audit itself can only report a
  permission gap *after* it has come back blind; this asks the same question up front.
  The affected-check lists are derived from the registry's declared cache wiring rather
  than hand-maintained, so a check added later is covered without editing the map.

- **`--digest`** on `sf audit security` — a compact result for programmatic callers.
  Passing checks are counted but not listed, `detail` prose gives way to `remediation`,
  and affected-item lists — unbounded, and the bulk of a large org's report — collapse to
  a count plus a three-item sample. Attack chains survive intact. Composes with `--json`,
  so an agent gets one command and compact stdout.

## [v1.9.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.9.0) — 2026-09-07

Two compliance catalogs, three attack chains, and a restructured documentation set — but
the reason to upgrade is the `--fail-on` fix. That flag never worked: any pipeline using it
exited 1 on every run, whatever the org looked like. If you gate CI on this plugin, this is
the release that makes the gate mean something.

### Fixed

- **`--fail-on` fired on every audit.** The threshold comparison ranked findings with
  `ORDER.indexOf(level) <= threshold`, and `INFO` is absent from that order, so it
  scored `-1` — more severe than `CRITICAL` at every threshold. Because passing and
  inconclusive checks both carry `INFO`, and every audit produces passes, any pipeline
  using `--fail-on` exited 1 regardless of what was actually found. Gateable severities
  are now matched explicitly, and passed/inconclusive findings can never be violations.

### Added

- **`--fail-on-inconclusive`** — exit 3 when a check could not gather evidence, so CI can
  tell a clean org apart from an audit user that could not see enough to judge. Off by
  default. A finding at or above `--fail-on` still takes precedence and exits 1.

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
