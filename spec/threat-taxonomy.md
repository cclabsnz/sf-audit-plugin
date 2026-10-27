# Threat taxonomy

STRIDE, LINDDUN, MITRE ATT&CK, abuse cases and OWASP, each attached at the layer it describes:

| Framework | Kind | Attaches to | Renders as |
|---|---|---|---|
| OWASP (Top 10, API Top 10) | control catalog | check, via `CHECK_CONTROL_MAP` | compliance matrix (existing) |
| STRIDE | security threat category | check | threat view, grouped by category |
| LINDDUN | privacy threat category | check, privacy-relevant only | threat view, privacy section |
| MITRE ATT&CK | adversary technique | `Capability`, so every chain step | chain steps, SARIF tags |
| Abuse case | misuse narrative | `NamedChainDef` | executive report, chain detail |

STRIDE, LINDDUN and ATT&CK form a taxonomy layer (`src/threats/`) beside `src/compliance/`, not inside it.

## Shape

- `src/threats/stride.ts`: `CHECK_STRIDE_MAP: Record<checkId, StrideCategory[]>`, where `StrideCategory` is `'S' | 'T' | 'R' | 'I' | 'D' | 'E'` and the primary category comes first
- `src/threats/linddun.ts`: `CHECK_LINDDUN_MAP: Record<checkId, LinddunCategory[]>`, where `LinddunCategory` is `'L' | 'I' | 'N' | 'D' | 'DD' | 'U' | 'NC'` (Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness & unintervenability, Non-compliance)
- `src/threats/attack.ts`: `TechniqueDef { id, name, tactics, version, url, verified }` catalog, plus `CAPABILITY_TECHNIQUES: Record<Capability, string[]>`
- `Finding.threats?: { stride: StrideCategory[]; linddun: LinddunCategory[] }`, populated by `CheckEngine` next to `complianceTags`
- `NamedChainDef.abuseCase: { actor, goal, preconditions, breakPoint }` (see RULE-110)

## RULE-100 Threat categories stay out of the compliance layer
cites: INT-014, MN-058
- When the compliance catalog, `Framework` union, framework packs or compliance matrix are built
- then no STRIDE, LINDDUN or ATT&CK identifier appears in them
- and `--frameworks` accepts no threat-taxonomy alias

## RULE-101 Every check carries a STRIDE category
cites: INT-014
- When a check id is registered (every key of `CHECK_CONTROL_MAP` and every check the engine runs)
- then `CHECK_STRIDE_MAP` gives it one or two categories, the primary one first
- and a test fails, naming the check, when a registered check has no entry or an entry names a check that does not exist

## RULE-102 LINDDUN is tagged only where personal data is at stake
cites: INT-014
- When a check concerns who can see, link, identify or retain personal data (guest and external exposure, sharing, field-level security, content links, data classification, field history, event monitoring, audit trail retention, data export)
- then `CHECK_LINDDUN_MAP` gives it its LINDDUN categories
- and a check with no privacy bearing has no entry; there is no default category

## RULE-103 Logging is read both ways
cites: INT-014, MN-061
- When a check is tagged STRIDE `R` and also LINDDUN `N` or `D` (`audit-trail`, `field-history-tracking`, `event-monitoring`, `apex-logging`, `siem-integration`)
- then the threat view states both readings: missing logging weakens repudiation defences, and logging personal data beyond need is itself a privacy threat
- and neither reading suppresses or downgrades the other

## RULE-104 The threat view reports coverage, not assurance
cites: INT-014, MN-058
- When the threat view is rendered
- then it lists every STRIDE category, and every LINDDUN category when any privacy check ran, with its active findings and the number of checks that cover it
- and a category with covering checks but no findings says "no findings from N checks"; a category no check covers says "not assessed by this tool"
- and it never says "pass", "compliant" or "no threats" for a category

## RULE-105 Threat tags carry no weight
cites: INT-014, MN-062
- When findings are scored, graded or filtered by `--fail-on`
- then `threats` and ATT&CK techniques are ignored; the same findings with and without tags produce the same score, grade and exit code

## RULE-106 ATT&CK techniques attach to capabilities, not checks
cites: INT-014
- When a finding grants or requires a `Capability`
- then its techniques are the verified techniques in `CAPABILITY_TECHNIQUES` for that capability
- and no check maps to a technique directly; a check reaches ATT&CK only through the capabilities it grants

## RULE-107 ATT&CK techniques have provenance
cites: INT-014, MN-059
- When a technique is catalogued
- then it carries its ATT&CK id, name, tactics, the pinned ATT&CK version (e.g. `ATT&CK v18`) and its attack.mitre.org url, and is `verified: false` until checked against that version and recorded in `docs/compliance/verification-worksheet.md`
- and an unverified technique is never rendered: a chain step whose capability has no verified technique renders without one, never with a guess

## RULE-108 Detection gaps map to evasion, not to access
cites: INT-014, MN-059
- When a finding reports missing detection (`audit-trail`, `event-monitoring`, `siem-integration`, `apex-logging` gaps)
- then it may reference the defence-evasion technique it leaves undetected (e.g. Disable or Modify Cloud Logs) as `detects`, never as a technique the finding grants
- and it does not add a step to any attack chain

## RULE-109 Every capability has a technique before ATT&CK renders
cites: INT-014, MN-059
- When ATT&CK output is switched on for a release
- then every member of `ALL_CAPABILITIES` has at least one verified technique, and a test enforces it

## RULE-110 Named chains are structured abuse cases
cites: INT-014, INT-012, MN-056
- When a `NamedChainDef` is defined
- then it carries `abuseCase`: `actor` (a role such as "unauthenticated site visitor", never a person), `goal` (the harm, in the attacker's terms), `preconditions` (the finding ids or id groups the chain matches on) and `breakPoint` (the finding ids whose remediation alone stops the chain)
- and its steps render as capability → technique pairs (RULE-106)
- and the existing `narrative` stays, as the prose form of the same abuse case

## RULE-111 A break point breaks the chain
cites: INT-014, MN-060
- When the active findings that make a chain fire have the `breakPoint` findings removed
- then the chain's `match()` returns null
- and each named chain has a test with a firing fixture and the same fixture minus its break point, asserting fire and no-fire

## RULE-112 Abuse cases name roles and shapes, never client specifics
cites: INT-014
- When an abuse case is rendered
- then its actor, goal and steps use roles, capability names and counts; object names, user names and org ids from the audited org appear only in the member findings' affected items, as today

## RULE-113 Every output carries the taxonomy in its own idiom
cites: INT-014, MN-058, MN-059
- When the JSON output is written, then each finding carries `threats` and each chain step its verified technique ids
- When SARIF is written, then rule `properties.tags` gain `stride:<C>`, `linddun:<C>` and, for chain results, `attack:<id>`
- When Markdown, HTML or the executive report is written, then it adds the threat view (RULE-104) after the compliance section, and the executive report lists each fired chain as an abuse case: actor, goal, steps, break point
- and the compliance matrix is unchanged

## RULE-114 OWASP Top 10:2025 sits beside 2021
cites: INT-014, MN-059
- When the OWASP catalog is extended
- then Top 10:2025 controls are added under their own ids and pinned version, and the 2021 ids, mappings and report output are unchanged
- and a 2025 control renders only once verified; A04-equivalent design categories stay declared out of scope

## RULE-115 API-surface checks map to the OWASP API Security Top 10
cites: INT-014, MN-059
- When a check assesses an API surface (`apex-rest-endpoint`, `connected-apps`, `api-client-permission`, `integration-least-privilege`, `guest-api-access`, `soap-login-api-auth`)
- then it also maps to the matching OWASP API Security Top 10:2023 control, catalogued with provenance, selectable with `--frameworks owasp-api`

## Draft mappings (to verify, not to render)

Starting point for RULE-101 and RULE-106. Every ATT&CK id below is `verified: false` until checked against the pinned version.

| Capability | Candidate techniques |
|---|---|
| `unauth-foothold` | T1190 Exploit Public-Facing Application |
| `low-trust-authenticated` | T1078.004 Valid Accounts: Cloud Accounts |
| `data-read` / `data-read-bulk` | T1213 Data from Information Repositories, T1530 Data from Cloud Storage |
| `data-write` | T1565 Data Manipulation |
| `code-exec` | T1059.009 Command and Scripting Interpreter: Cloud API |
| `credential-theft` | T1528 Steal Application Access Token, T1552 Unsecured Credentials |
| `priv-esc` | T1098 Account Manipulation, T1548 Abuse Elevation Control Mechanism |
| `org-takeover` | T1098 Account Manipulation, T1136.003 Create Account: Cloud Account |
| `external-egress` | T1567 Exfiltration Over Web Service |
| detection gaps (RULE-108) | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |

| STRIDE | Example checks (primary category) |
|---|---|
| S | `mfa-enforcement`, `sso-enforcement`, `login-session`, `password-session-policy`, `auth-providers` |
| T | `deployment-identity`, `installed-packages`, guest write access |
| R | `audit-trail`, `field-history-tracking`, `event-monitoring`, `apex-logging`, `siem-integration` |
| I | `sharing-model`, `field-level-security`, `content-links`, `hardcoded-credentials`, `named-credentials` |
| D | `api-limits`, `certificate-expiry`, guest hard delete |
| E | `permissions`, `users-and-admins`, `apex-sharing`, `flows-without-sharing`, `apex-crud-fls` |

## Not in rules

- **The tool's own threat model.** `docs/TRUST.md` gains a STRIDE pass over sf-audit itself (the org session it holds, waivers as a tamper target, reports as a disclosure target) and a LINDDUN pass over report content (people named in affected items, report retention). Documentation, not behaviour.
- **Order.** RULE-100–105 (STRIDE, LINDDUN, view), then 106–109 (ATT&CK behind the gate), then 110–112 (abuse cases), then 114–115 (OWASP catalogs). RULE-113 lands piecemeal with each.
- **In-flight work.** `feat/vishing-connected-app-chain` adds a named chain; whichever lands second adopts the other's shape (RULE-110 `abuseCase` and a RULE-111 break-point test).
