# Changelog

All notable changes to `@cclabsnz/sf-audit` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry mirrors the [GitHub Release](https://github.com/cclabsnz/sf-audit-plugin/releases) for that tag, which is the canonical
published note and carries the signed provenance attestation and CycloneDX SBOM for the build.

## [Unreleased]

## [v1.24.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.24.0) — 2026-10-30

Several checks were filtering on values the platform never writes, so they found nothing; they now
find what they look for. Guest exposure is graded one way, Apex follows the API 67.0 sharing and
user-mode defaults, and MFA registration reads every method. Some grades will fall where exposures
are newly found, and some will rise where findings were overstated.

### Added

- **An optional permission set for MFA registration**, `docs/permissionset/SF_Audit_MFA.permissionset-meta.xml`, separate from the read-only one. Salesforce grants "Manage MFA in API" only with user-management permissions, so it is meant for an audit user who is already an administrator.

- **`docs/FEATURES.md` lists what sf-audit already does**: commands, checks, attack chains, renderers, shared helpers, framework mappings and test tooling, each with its file. Search it before building something. A test fails when a check, chain, command, shared helper, renderer or chain module is missing from it.
- **The schema guard catches filters that match nothing.** The schema snapshot now keeps picklist values (all but geography, locale, currency and encoding lists, and without custom or namespaced values), and a query that filters on a value the picklist does not have fails the guard. A new deep-path guard seeds a consistent org so checks get past their first empty result, and validates the queries behind it.

### Security

- **deepmerge is pinned to 4.1.1 under jest.** GHSA-gcqx-w48m-w2h4 (prototype poisoning in `mergeObject()`, low) affects 4.2.0 to 4.3.1 and has no patched release. deepmerge reaches the project only through `jest-config`, a development dependency, and jest runs unchanged on 4.1.1, which is outside the affected range.

### Fixed

- **Guest-executable Apex is found again.** The check read Apex class access by filtering `SetupEntityAccess.ParentId` on the guest profile Ids. That field holds permission set Ids, so in a real org it matched nothing and reported "Guest profiles cannot execute any Apex classes". It now reads the guest users' permission sets, both the one each guest profile owns and any assigned to the guest. Some orgs will see new `guest-executable-apex-*` findings and the unauthenticated bulk-exfiltration chain they open, so some grades may fall.
- **The unauthenticated bulk-exfiltration chain needs the guest to reach the data itself.** The bulk read, write or code execution must now come from one of its guest-side steps. Before, an internal user's View All Data or an admin's Author Apex, together with any guest exposure, was enough to fire it. The potential-chain pass no longer pairs a guest foothold with those internal grants either.
- **The same chain no longer counts Apex or Flow that is only shown to run without sharing.** `portal-exposed-apex-without-sharing` flags classes with `@AuraEnabled`, `@RemoteAction` or `@RestResource` methods that lack sharing enforcement, and `flows-*-without-sharing` flags flows by run mode. Neither shows that a guest can call them. Guest-callable Apex is counted through `guest-executable-apex-*`.
- **A public external OWD on a guest-readable object no longer makes it CRITICAL.** Secure guest record access has been enforced since Winter '21, so the external OWD alone gives guests nothing: record sharing gives a guest a record only through sharing or ownership. `guest-object-exposure-public-owd` now needs `UserRecordAccess` to show that a guest user (every site's guest user is checked) can read one of up to 200 sampled records, and it is HIGH, like every other way records are shared with guests (see below). An object whose records a guest user owns stays CRITICAL as `guest-object-exposure-guest-owned`. Otherwise the check reports the new MEDIUM finding `guest-object-exposure-public-owd-unconfirmed`, which feeds no attack chain and notes whether the probe ran.
- **The unauthenticated bulk-exfiltration chain needs a step that reaches records.** Guest API access, guest object permissions, or guest-callable Apex not shown to bypass sharing reach nothing on their own under secure guest record access, yet any one of them, beside a guest user existing, fired a CRITICAL chain. The potential-chain pass does not report them as a guest path either. One step must now show the guest reaching records: a guest sharing rule, guest-owned or confirmed-readable records, the whole User roster, guest-callable Apex that runs without sharing, or secure guest record access not being enforced.
- **The flows-without-sharing check flags the flows it names.** It flagged autolaunched and screen flows in Default Mode, where a screen flow runs as the user, and missed flows explicitly set to run in system context without sharing. It now flags autolaunched and screen flows explicitly set that way, so most orgs will see fewer of these findings and some will see new ones. Record-, schedule- and platform-event-triggered flows always run that way, have no setting to change, and are not flagged.
- **Guest exposure findings say what a guest can do.** Affected items read "guest Create permission" instead of "guest WRITE": guests cannot hold Edit or Delete since Winter '21. The guest-owned remediation now says to reassign existing records, instead of enabling two settings the platform has enforced since Winter '21.
- **Guest sharing rules are found.** The guest-access and public-group sharing checks counted share rows with `RowCause = 'SharingRule'`, a value the platform never writes, so they found no sharing rule at all. They now count `Rule`, and the guest check also counts `GuestRule`, the value guest user sharing rules write. Orgs with guest or public-group sharing rules will see new findings, and some grades may fall.
- **MFA registration covers the same users as the count.** Frozen users are now dropped from the registrations, as they already were from the count, and the 2000-row cap is gone.
- **Apex classes saved at API 67.0 or later are no longer reported for a missing sharing keyword.** From Summer '26 an Apex class compiled at API 67.0 or later that declares no sharing keyword runs with sharing. The guest-executable Apex, Apex sharing and Apex REST endpoint checks now read each class's API version. They report a keyword-less class only when it, or a keyword-less parent it inherits from, is below 67.0, or when its version cannot be read. A keyword-less guest-callable class at 67.0 drops from CRITICAL to the HIGH "executable by guests" finding, so some grades may rise. The REST check now also follows inheritance: an endpoint that extends a `without sharing` class is reported as without sharing.
- **A keyword-less class reached only from Aura or LWC is no longer reported as running without sharing.** Since Winter '21 an `@AuraEnabled` call into a class with no sharing keyword runs with sharing. A class whose only way in is `@AuraEnabled` (no REST, SOAP, remoting or Visualforce use) leaves the guest CRITICAL finding and the portal-exposed list. The Apex sharing check still lists it below API 67.0 as missing a keyword.
- **Apex saved at API 67.0 or later is no longer reported for missing CRUD/FLS checks.** From that version queries and DML run in user mode by default, which enforces object and field permissions. SYSTEM_MODE in such a class is still reported.
- **Records shared with guests are found, whatever the object's OWD.** The guest object exposure check looked only for guest-owned records when an object's external OWD was Private, so it missed guest user sharing rules, the main way a guest reaches records under secure guest record access. The guest-access check looked only at sharing-rule rows naming the guest user. Both now read share tables the same way. A row gives guests access when it comes from a guest sharing rule, or from the parent or person-account access one implies, whoever it names. It also counts when it is a manual, Apex or group share naming a guest user or a public group or queue a guest belongs to. Winter '21 did not remove those. The guest-access check reports Account, Case, Contact and Opportunity (`guest-user-sharing-exposure`). The guest object exposure check reports every other guest-readable object as the new HIGH finding `guest-object-exposure-guest-shared`, falling back to `UserRecordAccess` on a sample when the share table shows nothing or cannot be read. Shares to a site's guest user group count too, and group membership is followed through nested groups. The guest-access check also asks `UserRecordAccess` on a sample when Account, Case, Contact or Opportunity show no share row, or the share table cannot be read: for example a Contact controlled by its parent. It asks only where a guest can read the object and owns none of its records. The guest object exposure check leaves those four objects to it, except for guest-owned records, so each exposure is reported once.
- **Guest object access is found again.** The guest-access check filtered `ObjectPermissions.ParentId` on the guest profile Ids. That field holds permission set Ids, so it never found a guest Read, Create, Edit or Delete on Account, Contact, Case, Lead or Opportunity, and `guest-user-read-access` and `guest-user-write-access` could not fire. It now reads the guest users' permission sets: the one each guest profile owns, and any assigned to a guest. Some orgs will see these findings for the first time, and some grades may fall. It is HIGH, not CRITICAL, because a guest sharing rule is how a site publishes records on purpose: the finding asks the org to confirm they are meant to be public. Share rows on a public-OWD object are graded the same way, since the external OWD does not reach guests. All of these count as the guest reaching records in the unauthenticated bulk-exfiltration chain, which still needs a guest step that reads in bulk, writes or runs code (guest API access, guest-owned records, guest-callable Apex without sharing). Guest-owned records remain the CRITICAL bulk sink. Some grades may fall.
- **A public external OWD on User no longer counts as a guest exposure.** Secure guest record access keeps the guest OWD Private on every object, User included, so `guest-user-visibility-owd` shows the staff roster to logged-in portal and community users, not to guests. It is now MEDIUM instead of HIGH, says who it reaches, is reported whether or not the org has a guest user (but only when it has an active external user or an Experience Cloud site, so someone can be reached), and feeds the low-trust chains (such as self-registration) instead of the unauthenticated one.
- **Guest member visibility counts only on live sites, and as a read.** "Let guest users see other members of this site" shows a live site's members to guests. It now joins the unauthenticated chain as a step when that chain fires, but it opens no chain, unauthenticated or low-trust, since it shows members, not business records. On a site that is not live it is reported apart, at LOW, as `guest-site-options-member-visibility-not-live`.
- **MFA registration reads every method.** The check read `TwoFactorInfo`, whose `Type` can only be `TOTP`, so users registered with Salesforce Authenticator, a security key or a built-in authenticator counted as unregistered (`TwoFactorInfo.Type` has `TOTP` as its only picklist value). It now reads `TwoFactorMethodsInfo`. An authenticator app, Salesforce Authenticator, a security key or a built-in authenticator counts as registered. A verified phone number or email address, or a temporary code, does not: those are sign-in fallbacks. Only registered users go to the method strength check, with every method they hold. A user with just a phone number or email address is reported as unregistered, not graded as having weak MFA, so an admin who verified an email address no longer rates worse than one who did nothing. Preflight now reports the permission as optional. The object needs "Manage MFA in API", which Salesforce grants only with user-management permissions. It is therefore optional and not in the read-only permission set; see PERMISSIONS.md.
- **The guest User visibility check no longer looks for a Read grant on User.** User takes no object permissions, so `ObjectPermissions` never holds a User row (a Developer Edition org had none across all its permission sets, against 141 for Account), and `guest-user-visibility-object-read` could never fire. The leg and its finding are removed. Guest access to the roster is still reported through View All Users and a site's guest member visibility.
- **The guest read probe samples both ends of an object's history.** It took the first 200 records in no order, so a share matching only recent records could read as no guest access. It now samples the 100 most and 100 least recently changed records, and falls back to an unordered sample when the object cannot be ordered.
- **Guest file access counts only on live sites.** As with member visibility, a site that is not live is reported apart, at LOW, as `guest-site-options-file-access-not-live`, and feeds no chain.
- **The Apex REST check reads `without sharing` from code.** A comment or string containing the words no longer marks an endpoint as running without sharing. An inner class declared `without sharing` still counts.
- **Three checks filtered on values the platform never writes, so they found nothing.** Salesforce accepts a filter on a picklist value that does not exist and matches no rows, so these checks passed in every org:
  - **SSO enforcement** looked for `LoginType = 'Username-Password'`. Credential logins are recorded in `LoginSubType` (`UI Username-Password`, `OAuth Username-Password`), which the check now reads. Orgs where users still log in with Salesforce credentials will see the finding.
  - **Public group sharing** looked for the All Internal Users group as `Group.Type = 'AllInternal'`. That group's type is `Organization`. Orgs that share records to All Internal Users through sharing rules will see the finding.
  - **Release updates** also asked for a `Revoked` status, which does not exist. The check's results do not change.
  Some grades may fall.

## [v1.23.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.23.0) — 2026-10-29

Attack chains and checks now match what the platform does. One chain is re-rated, so some grades may
rise.

### Changed

- **`cred-theft-pivot` is rated HIGH, not CRITICAL.** Its secret is found by pattern match. Its egress steps are mostly the org's own registered endpoints, which give an attacker who holds the secret nothing new. Orgs where this chain fires no longer count it as a critical chain in the grade.

### Fixed

- **The unauthenticated bulk-exfiltration chain no longer counts external sharing defaults as an unauthenticated step.** Guest record access has been secured since Winter '21, so the external OWD reaches logged-in portal users, not guests. Those findings stay in the low-trust chains, such as self-registration.
- **The hardcoded-credential check no longer flags a value read at run time.** A credential parameter built from a stored value, such as `'client_secret=' + EncodingUtil.urlEncode(cfg.Secret__c, 'UTF-8')`, was matched as a hardcoded secret.
- **The CRUD/FLS finding gives the CRUD/FLS remedy.** It now leads with `WITH USER_MODE` or `Security.stripInaccessible()`. Before, it led with "with sharing", which enforces record sharing only and duplicated the sharing finding's advice.
- **The self-registration chain tells one story.** It no longer calls self-registration "not a finding" while making it the break point. Its remediation leads with turning self-registration off, or with a custom registration handler that approves accounts.
- **Each attack-scenario slide states its chain's rating against its steps.** This covers a chain rated above its steps, and a chain whose critical step is also counted on its own in the grade.
- **MFA results no longer read as assurance about nobody.** When no active standard user is visible, the registration check is now inconclusive instead of "All 0 users have registered". The audit user is itself one, so a count of 0 means the users could not be seen. When no one has registered a method, the method-strength check reports an informational "not graded" finding instead of a pass, and notes that this is expected with single sign-on.
- **The executive scope statement matches what the audit reads.** It reads configuration, metadata, selected records and event logs, including pattern-based static checks of Apex and Flow. It is not a penetration test or a code review. Readers are asked to confirm each finding in the org.

## [v1.22.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.22.0) — 2026-10-29

The executive report is now a consulting-style deck that leads with what to do, with the threat
model on its own slides.

### Changed

- **The executive report is now a consulting-style deck.** Every slide's title states its conclusion, and a note under each exhibit says where its numbers come from. In order:
  - **Cover**: grade and health score, kept small.
  - **Executive summary**: situation, complication and resolution.
  - **Where to act**: the actions placed on risk removed against effort.
  - **Action plan**: ranked actions in three waves (start now, next 30 days, this quarter). For each, what it breaks, the findings it closes, effort, and an owner to agree.
  - **Threat model**: a MITRE ATT&CK slide (findings per tactic, and the tactics each attack chain reaches) and a STRIDE and LINDDUN heatmap.
  - **Attack scenarios**: one slide per named attack chain, and one for the potential chains.
  - **Appendix and sign-off**: roadmap, compliance, findings, and a sign-off page.
- **Actions are computed, not listed.** Each named chain's break point becomes the action that breaks it (chains sharing a break point share it). Every other open critical or high finding becomes an action per check. Actions are ranked by the risk they remove, with a broken chain counting double.
- **It prints one slide per landscape A4 page.** Every printed page names its client, date and page. Fonts are Source Serif 4 and Source Sans 3, embedded so the report never fetches anything. A firm's own colours and fonts still apply when it has set them.

## [v1.21.1](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.21.1) — 2026-10-28

### Fixed

- **The CORS allowlist check no longer overstates the risk.** Its findings said a wildcard origin enabled "token theft" and "authenticated cross-origin requests". An allowlist entry supplies no credential: script on an allowed origin can use the org's APIs from a user's browser only with a session ID or OAuth token it already has, except for a Lightning Out app shared with guest users. The findings now say so. Severity is unchanged.

## [v1.21.0](https://github.com/cclabsnz/sf-audit-plugin/releases/tag/v1.21.0) — 2026-10-28

Findings and attack chains now name the MITRE ATT&CK techniques an attacker would use, and chain
steps are listed in the order an attack would run.

### Added

- **MITRE ATT&CK techniques on findings.** A finding carries the techniques for the attacker capabilities it grants, never for the check that raised it: as `threats.attack` in JSON, an **ATT&CK** line in Markdown, `attack:<id>` rule tags in SARIF, and a technique label on each attack-chain step in Markdown and HTML (SARIF steps carry `attackTechniques`). Techniques are pinned to Enterprise ATT&CK v20.0, and only techniques whose id, name, tactics and fit are recorded in the verification worksheet are ever shown. Where a capability's usual technique does not fit a finding, the finding names its own or none.
- **Detection gaps say what goes unseen.** A finding showing that nothing alerts on suspicious logins carries the techniques it leaves unobserved (`threats.detects`, "leaves unobserved" in Markdown), kept apart from the techniques a finding grants.
- **Chain steps follow the ATT&CK tactic order.** Steps of named and potential chains are listed from the earliest tactic (initial access) to the latest (exfiltration, impact). Ordering moves steps only; the break point, severity and score are unchanged.

### Changed

- **Active debug traces no longer count as an exposed secret.** The finding fires on a trace at any log level, and only View All Data users can read debug logs, so it grants no attacker capability. It no longer feeds `cred-theft-pivot`, nor the potential chain from an unauthenticated foothold to credential theft.
- **Wildcard and broad CORS origins no longer count as an exposed secret.** An allowlist entry exposes no stored credential; abusing one needs a controlled origin and a logged-in victim, and reaches only that user's own access. The findings keep their severity but no longer feed `cred-theft-pivot`, nor the potential chain from an unauthenticated foothold to credential theft.
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
