# Threat taxonomy

STRIDE, LINDDUN, MITRE ATT&CK, abuse cases and OWASP, each attached at the layer it describes:

| Framework | Kind | Attaches to | Renders as |
|---|---|---|---|
| OWASP (Top 10, API Top 10) | control catalog | check, via `CHECK_CONTROL_MAP` | compliance matrix (existing) |
| STRIDE | security threat category | check, overridable per finding | threat view, per-finding tags |
| LINDDUN | privacy threat category | check, privacy-relevant only | threat view, per-finding tags |
| MITRE ATT&CK | adversary technique | `Capability` a finding grants | chain steps, SARIF tags |
| Abuse case | misuse narrative | named chain (`NamedChainDef`) | executive report, chain detail |

STRIDE, LINDDUN and ATT&CK form a taxonomy layer (`src/threats/`) beside `src/compliance/`, not inside it.

## Shape

- `src/threats/stride.ts`: `CHECK_STRIDE_MAP: Record<checkId, StrideCategory[]>`, where `StrideCategory` is `'S' | 'T' | 'R' | 'I' | 'D' | 'E'` and the primary category comes first
- `src/threats/linddun.ts`: `CHECK_LINDDUN_MAP: Record<checkId, LinddunCategory[]>`, where `LinddunCategory` is `'L' | 'I' | 'Nr' | 'D' | 'DD' | 'U' | 'Nc'` (Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness & unintervenability, Non-compliance)
- `src/threats/attack.ts`: `TechniqueDef { id, name, tactics, version, url, verified }` catalog, `CAPABILITY_TECHNIQUES: Record<Capability, string[]>`, and an exported `ATTACK_OUTPUT_ENABLED` flag
- `Finding.threats?: { stride?: StrideCategory[]; linddun?: LinddunCategory[] }`: set inline by a check to override its check-level entry for one finding (as `capabilities` overrides the registry), otherwise populated by `CheckEngine` from the maps, next to `complianceTags`
- `AttackChainStep.capabilityInferred?: true` when the step's finding grants no capability and `ChainEngine.stepFor` fell back to `'data-read'`
- `NamedChainDef.abuseCase: { actor, goal, preconditions, breakPoint }` (RULE-110), where `preconditions` and `breakPoint` reference exported finding-id group constants, the same arrays `match()` uses (as `GUEST_EXPOSURE` already is)

## RULE-100 Threat categories stay out of the compliance layer
cites: INT-014, MN-058
- When the compliance catalog, `Framework` union, framework packs or compliance matrix are built
- then no `stride:`, `linddun:` or ATT&CK `T`-number identifier appears in them
- and `--frameworks` accepts no threat-taxonomy alias

## RULE-101 Every check carries a STRIDE category
cites: INT-014
- When a check is in `CHECKS` (src/checks/registry.ts)
- then `CHECK_STRIDE_MAP` gives it one or two categories, the primary one first
- and a test fails, naming the check, when a check has no entry or an entry names no check in `CHECKS`
- and a check whose findings differ in kind (guest read against guest write, API enabled against hard delete) sets `threats.stride` on those findings, which overrides the check-level entry

## RULE-102 LINDDUN is tagged only where personal data is at stake
cites: INT-014
- When a check concerns who can see, link, identify or retain personal data (guest and external exposure, sharing, field-level security, content links, data classification, data export, field history, event monitoring and audit trail retention, Apex logging of sensitive data, SIEM forwarding)
- then `CHECK_LINDDUN_MAP` gives it its LINDDUN categories
- and a check with no privacy bearing has no entry; there is no default category

## RULE-103 Logging is read both ways
cites: INT-014, MN-061
- When a finding is tagged STRIDE `R` and its check also carries LINDDUN `Nr` or `D` (`audit-trail`, `field-history-tracking`, `event-monitoring`, `apex-logging`, `siem-integration`)
- then the threat view gives both readings: the STRIDE reading is the repudiation gap the finding reports; the LINDDUN reading notes the privacy cost of the logging its remediation adds (what personal data it captures, how long it is kept, who can read it)
- and a finding that reports sensitive data being logged (e.g. Apex logging sensitive values) is a LINDDUN finding in its own right
- and neither reading suppresses or downgrades the other

## RULE-104 The threat view reports coverage, not assurance
cites: INT-014, INT-010, MN-058
- When the threat view is rendered
- then it lists every STRIDE category, and every LINDDUN category when any privacy-tagged check ran, with its active findings and the number of covering checks that gathered evidence
- and a category with covering checks that gathered evidence but no findings says "no findings from N checks"; a category whose covering checks all failed or were not assessed says "not assessed in this run"; a category no check covers says "not assessed by this tool"
- and it never says "pass", "compliant" or "no threats" for a category

## RULE-105 Threat tags carry no weight
cites: INT-014, MN-062
- When findings are scored, graded, filtered by `--fail-on`, or given a SARIF `security-severity`
- then `threats`, ATT&CK techniques and `abuseCase` are ignored; the same audit with and without them produces the same score, grade, exit code and `security-severity`

## RULE-106 ATT&CK techniques attach to granted capabilities, not checks
cites: INT-014
- When a finding grants a `Capability` (`capabilitiesFor(f).grants`)
- then it carries the verified techniques in `CAPABILITY_TECHNIQUES` for every capability it grants
- and a capability a finding only requires adds no technique to it
- and no check maps to a technique directly

## RULE-107 ATT&CK techniques have provenance
cites: INT-014, MN-059
- When a technique is catalogued
- then it carries its ATT&CK id, name, tactics, the pinned ATT&CK release it was checked against and its attack.mitre.org url, and is `verified: false` until checked against that release and recorded in `docs/compliance/verification-worksheet.md`
- and an unverified technique is never rendered: where no verified technique exists, the output shows none, never a guess

## RULE-108 Detection gaps reference what they leave unseen
cites: INT-014, MN-059, MN-062
- When a finding reports missing detection (`audit-trail`, `event-monitoring`, `siem-integration`, `apex-logging`, threat-detection and transaction-security gaps)
- then it may reference, as `detects`, the technique it leaves unobserved (its tactic comes from the catalog's `tactics`), never as a technique the finding grants
- and chains that already use detection gaps as steps (`insider-bulk-exfil`, `undetected-compromise`) keep them unchanged; those steps render with no ATT&CK technique

## RULE-109 Every capability has a technique before ATT&CK renders
cites: INT-014, MN-059
- When `ATTACK_OUTPUT_ENABLED` is true
- then every member of `ALL_CAPABILITIES` has at least one verified technique, and a test enforces it
- and while it is false, no output carries an ATT&CK technique

## RULE-110 Named chains are structured abuse cases
cites: INT-014, INT-012, MN-056
- When a `NamedChainDef` is defined
- then it carries `abuseCase`: `actor` (a role such as "unauthenticated site visitor", never a person), `goal` (the harm, in the attacker's terms), `preconditions` (the finding-id or id-prefix groups the chain matches on, or the capabilities it gates on) and `breakPoint` (one of those groups, whose complete removal stops the chain)
- and a step renders as capability → technique only when its finding grants that capability; a step with `capabilityInferred` renders without capability or technique
- and the existing `narrative` stays, as the prose form of the same abuse case
- and potential chains (`confidence: 'potential'`) carry no `abuseCase`

## RULE-111 A break point breaks the chain
cites: INT-014, MN-060
- When a fixture contains every finding id (or a finding per id prefix) the named chain matches on, and then every finding in its `breakPoint` group is removed
- then `ChainEngine.correlate` produces no chain with that id, with capabilities recomputed from the remaining findings
- and each named chain has a test asserting it fires on the full fixture and does not fire without its break point

## RULE-112 Abuse cases name roles and shapes, never client specifics
cites: INT-014
- When an abuse case is rendered
- then its actor, goal, steps and break point use roles, capability names, technique names and counts, never finding titles or finding ids (which can carry user names, agent labels and record ids)
- and per-step finding titles stay in the chain detail, as today

## RULE-113 Every output carries the taxonomy in its own idiom
cites: INT-014, MN-058, MN-059, MN-060
- When the JSON output is written, then each finding carries `threats` and each chain step its verified technique ids
- When SARIF is written, then rule `properties.tags` gain `stride:<C>`, `linddun:<C>` and, for chain results, `attack:<id>`
- When Markdown or HTML is written, then each finding shows its STRIDE and LINDDUN tags beside its compliance tags, and a threat view section (RULE-104) follows the findings
- When the executive report is written, then the threat view follows the compliance matrix, and each fired named chain is listed as an abuse case: actor, goal, steps, break point
- and the executive report's "Breaks the chain" line shows the chain's `breakPoint` (RULE-111), not `remediation`; potential chains show their remediation labelled "Recommended fixes"
- and the compliance matrix is unchanged

## RULE-114 OWASP Top 10:2025 is a separate framework
cites: INT-014, MN-059
- When the 2025 catalog is added
- then its controls sit under a new `Framework` value (`OWASP_2025`) with their own id prefix and pinned version, selectable by alias (`owasp-2025`), and are not added to the `universal` or `nz` packs
- and `--frameworks owasp` and every 2021 id, mapping and report output stay unchanged
- and A06:2025 Insecure Design (2021 A04) stays declared out of scope; A10:2025 Mishandling of Exceptional Conditions is declared in or out of scope explicitly; the 2021 A10 SSRF egress mappings are remapped to A01:2025, which absorbed SSRF, not copied
- and a 2025 control renders only once verified

## RULE-115 API-surface checks map to the OWASP API Security Top 10
cites: INT-014, MN-059
- When a check assesses an API surface (`apex-rest-endpoint`, `connected-apps`, `api-client-permission`, `integration-least-privilege`, `guest-api-access`, `soap-login-api-auth`)
- then it also maps to the matching OWASP API Security Top 10:2023 control, catalogued with provenance under a new `Framework` value (`OWASP_API`), selectable with `--frameworks owasp-api`, and not added to the `universal` or `nz` packs

## Draft mappings (to verify, not to render)

Starting point for RULE-101 and RULE-106. Every ATT&CK id below is `verified: false` until checked against a pinned release, and the fit is verified, not only the id.

| Capability | Candidate techniques |
|---|---|
| `unauth-foothold` | T1190 Exploit Public-Facing Application (fit to verify for misconfiguration rather than an exploit) |
| `low-trust-authenticated` | T1078.004 Valid Accounts: Cloud Accounts; T1136.003 Create Account: Cloud Account (self-registration) |
| `data-read` / `data-read-bulk` | T1213.004 Data from Information Repositories: Customer Relationship Management Software; T1530 Data from Cloud Storage |
| `data-write` | T1565.001 Data Manipulation: Stored Data Manipulation |
| `code-exec` | T1059.009 Command and Scripting Interpreter: Cloud API |
| `credential-theft` | T1528 Steal Application Access Token; T1552.001 Unsecured Credentials: Credentials In Files |
| `priv-esc` | T1098.003 Account Manipulation: Additional Cloud Roles; T1548 Abuse Elevation Control Mechanism |
| `org-takeover` | T1098 Account Manipulation; T1136.003 Create Account: Cloud Account |
| `external-egress` | T1567 Exfiltration Over Web Service |
| detection gaps, `detects` (RULE-108) | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |

| STRIDE | Example checks (primary category); finding-level overrides in brackets |
|---|---|
| S | `mfa-enforcement`, `sso-enforcement`, `login-session`, `password-session-policy`, `auth-providers` |
| T | `deployment-identity`, `installed-packages` [`guest-user-write-access` from `guest-user-access`] |
| R | `audit-trail`, `field-history-tracking`, `event-monitoring`, `apex-logging`, `siem-integration` |
| I | `sharing-model`, `field-level-security`, `content-links`, `hardcoded-credentials`, `guest-user-access` |
| D | `api-limits`, `certificate-expiry` [`guest-api-hard-delete` from `guest-api-access`] |
| E | `permissions`, `users-and-admins`, `apex-sharing`, `flows-without-sharing`, `apex-crud-fls` |

## Not in rules

- **The tool's own threat model.** `docs/TRUST.md` gains a STRIDE pass over sf-audit itself (the org session it holds, waivers as a tamper target, reports as a disclosure target) and a LINDDUN pass over report content (people named in affected items and finding titles, report retention). Documentation, not behaviour.
- **Order.** RULE-100–105 (STRIDE, LINDDUN, view), then 106–109 (ATT&CK behind the flag), then 110–112 (abuse cases, which also fix the "Breaks the chain" line), then 114–115 (OWASP catalogs). RULE-113 lands piecemeal with each.
- **In-flight work.** `feat/vishing-connected-app-chain` adds a named chain; whichever lands second adopts the other's shape (RULE-110 `abuseCase` and a RULE-111 break-point test).
- **Pre-existing.** `## RULE-001` appears twice in `spec/`; not touched here.
