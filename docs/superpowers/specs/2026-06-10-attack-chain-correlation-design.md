# Attack Chain Correlation — Design

**Date:** 2026-06-10
**Status:** Approved (pending spec review)

## Problem

Every check today emits standalone findings, each carrying its own severity. The
tool never reasons about how several individually-rated findings **combine** into an
exploit path that is more dangerous than any single one. An org can therefore show a
healthy grade while being fully exploitable — e.g. an active guest user (HIGH) plus a
`without sharing` Apex REST endpoint (HIGH) plus an exposed sensitive field (MEDIUM)
together enable unauthenticated bulk data exfiltration (CRITICAL), but nothing in the
report says so.

We want the tool to **capture** (find the combinations, including ones we didn't
hand-author) and **highlight** (surface the important ones loudly, with the right
grade impact) attack chains — without depending on any LLM or network access, so it
stays deterministic, offline, and CI-friendly.

## Approach

A **hybrid capability-graph engine with a thin curated layer**, run as a
post-processing pass in `CheckEngine.run()` after all checks have produced findings
and before `buildAuditResult()`.

- **Capability graph** guarantees breadth — emergent chains are discovered
  automatically as checks declare capabilities, so future checks participate for free.
- **Curated named chains** guarantee quality — the well-known, high-confidence paths
  get authoritative titles, fixed severities, narratives, and remediation.

LLM-based reasoning was rejected: the tool must run without API access.
A pure curated rule library was rejected: it only ever catches chains we personally
thought to write, which directly contradicts the goal of not missing combinations.

## Capability model

A small, fixed vocabulary. Findings **grant** capabilities; chains **require** them.

| Capability | Meaning |
|---|---|
| `unauth-foothold` | Unauthenticated access surface exists (active guest user, public site, self-registration) |
| `low-trust-authenticated` | Low-trust authenticated foothold (portal/community user) |
| `data-read` | Can read business data |
| `data-read-bulk` | Can mass-read / export data |
| `data-write` | Can create/modify/delete records |
| `code-exec` | Can execute server-side Apex in some reachable context |
| `credential-theft` | Can obtain secrets/tokens (hardcoded creds, broad CORS, debug logs) |
| `priv-esc` | Can elevate privileges (assign perm sets, manage users, author apex, modify metadata) |
| `org-takeover` | Effectively full org control (Modify All + Manage Users) |
| `external-egress` | A path to move data out of the org (named credential, remote site, email service) |

The vocabulary is intentionally small and closed. Adding a capability is a deliberate,
reviewed change.

## Components

### `src/chains/Capability.ts`
Exports the `Capability` union type and any grouping constants (e.g. `SOURCE_CAPS`,
`HIGH_IMPACT_SINKS`).

### `src/chains/CapabilityRegistry.ts`
A single central map: finding `id` → `{ grants?: Capability[]; requires?: Capability[] }`.
Rationale: for a security feature the entire attack model should live in one reviewable
file, and the ~75 existing checks stay untouched (low blast radius). Only **active**
findings (not `passed`, not `inconclusive`) contribute their grants.

New checks may additionally declare capabilities inline via an optional
`capabilities?: { grants?; requires? }` field on `Finding`, for locality. When both are
present, the inline value wins for that finding.

### `src/chains/AttackChain.ts`
```ts
export interface AttackChain {
  id: string;
  title: string;
  severity: RiskLevel;            // CRITICAL..LOW
  confidence: 'named' | 'potential';
  narrative: string;              // how the steps combine into an exploit
  remediation: string;
  steps: Array<{ findingId: string; checkId?: string; capability: Capability }>;
}
```

### `src/chains/namedChains.ts`
The curated seed set (see below). Each named chain declares the capability set it
requires and a function/selector that picks the concrete member findings to cite as
steps.

### `src/chains/ChainEngine.ts`
```ts
correlate(findings: Finding[]): AttackChain[]
```
1. Compute the set of capabilities present from active findings (registry + inline).
2. **Named pass:** for each named chain whose required capabilities are all present,
   emit an `AttackChain` with `confidence: 'named'`, citing the specific member
   findings as steps.
3. **Emergent pass:** graph walk from any source capability
   (`unauth-foothold`, `low-trust-authenticated`) toward any high-impact sink
   (`org-takeover`, `data-write`, `data-read-bulk`, `credential-theft`). Guards:
   - max path length 4 steps;
   - dedupe by capability-signature;
   - suppress any path already covered by a named chain;
   - remaining paths emitted as `confidence: 'potential'`, severity capped at HIGH.
4. Return named chains first (by descending severity), then potential chains.

## Seed named chains

| id | Title | Severity | Requires (capabilities) |
|---|---|---|---|
| `unauth-bulk-exfil` | Unauthenticated bulk exfiltration | CRITICAL | `unauth-foothold` + (`code-exec` \| `data-read-bulk`) on data |
| `standard-to-takeover` | Standard user → org takeover | CRITICAL | `low-trust-authenticated` + `priv-esc` → `org-takeover` |
| `cred-theft-pivot` | Credential theft → external pivot | CRITICAL | `credential-theft` + `external-egress` |
| `soql-injection-read` | SOQL injection → mass read | HIGH | `code-exec` (injectable) + `data-read-bulk` |
| `mfa-bypass-admin` | MFA bypass → privileged compromise | HIGH | (MFA-not-enforced \| trusted-IP-bypass) + admin perms present |

Member-finding sources (examples): `guest-user-*`, `guest-executable-apex`,
`apex-sharing` (portal/without-sharing), `sharing-model-external-read`,
`field-level-security`, `escalation-perms`, `permissions`, `users-admins`,
`hardcoded-credentials`, `custom-labels-credential`, `debug-log-access`,
`cors-allowlist`, `named-credentials`, `remote-sites`, `soql-injection-risk`,
`mfa-enforcement`, `trusted-ip-ranges`.

## New checks (chain ingredients)

### `guest-executable-apex` (category: Access Control)
Joins guest and low-trust profiles to the Apex classes and Visualforce pages they can
invoke via `SetupEntityAccess`, flagging classes that are `without sharing` or perform
unprotected SOQL/DML. This is the classic real-world Salesforce breach chain. Grants
`code-exec` (combined with `unauth-foothold` from guest presence).

### `cors-allowlist` (category: External Connectivity)
Queries `CorsWhitelistEntry` for wildcard or overly broad origins that allow malicious
sites to issue authenticated browser requests and read session-scoped responses.
Grants `credential-theft`.

### `escalation-perms` (category: Permissions)
Extends the existing admin-permission cluster with the lateral-movement / persistence
primitives not covered today: `ManageInternalUsers`, `AssignPermissionSets`,
`ModifyMetadata`, `ManageAuthProviders`, `ManageConnectedApps`, `ManageSession`,
`PasswordNeverExpires`, `ViewAllUsers`. Grants `priv-esc`.

## Scoring & result

`AuditResult` gains `attackChains: AttackChain[]`.

In `buildAuditResult()`:
- Each chain scores like a finding: its severity weight (from the existing
  `riskScores`) is added to the numerator and `+10` to `maxPossible`. Member findings
  keep their own severities — no double-counting of the parts.
- Chain severities fold into the `criticalCount` / `highCount` / `mediumCount` totals
  passed to `meetsConditions()`. This is the lever that prevents an org with a live
  CRITICAL chain from earning an A.

No new scoring config is required for v1; chains reuse `riskScores`. (A future
`chainWeights` override can be added if needed.)

## Report

A new **Attack Paths** section renders **first**, above the individual findings, in:
- `HtmlRenderer` — collapsible cards, severity badge, narrative, numbered steps that
  deep-link to the member findings.
- `MarkdownRenderer` — heading + ordered steps.
- `JsonRenderer` — `attackChains` array.

`DiffRenderer` / `HistoryRenderer` are **out of scope** for v1.

## Testing (TDD)

- **ChainEngine** — given fixed finding sets + registry, assert expected named and
  emergent chains; assert emergent suppression when covered by a named chain; assert
  path-length guard and capability-signature dedupe.
- **New checks** — one test each with mocked SOQL/Tooling clients (positive, negative,
  and inconclusive/permission-error paths), following the existing check test style.
- **Scoring** — chains contribute to score and to grade gating; a CRITICAL chain caps
  the grade.
- **Registry integrity** — every key in `CapabilityRegistry` and every finding id
  referenced by a named chain resolves to a finding id that some check can emit
  (guards against silent rot when ids change).

## Out of scope (v1)

- Diff/History rendering of chains.
- Configurable chain weights.
- Chains spanning more than 4 capability hops.
- The remaining gap checks from the earlier review (#4 LWC/Aura XSS, #5 inbound email,
  #6 mass-export, #7 named-cred SSRF flags, #8 login flows) — tracked separately.
