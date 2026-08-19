# Architecture

How `@cclabsnz/sf-audit` is put together, and why the boundaries sit where they do. For what it
checks see [CHECKS.md](CHECKS.md); for how to run it see [COMMANDS.md](COMMANDS.md).

## Shape

An oclif plugin for the Salesforce CLI. One command does the audit; five others work with what it
produced or with captured event logs. There is no server, no daemon and no state outside the
operator's machine.

```
sf audit security ──> CheckEngine ──> 88 SecurityChecks ──> Findings
                           │                  │
                           │                  └──> AuditCache (shared query results)
                           │
                           ├──> ChainEngine ────> AttackChains
                           ├──> compliance/resolve ──> ControlDefs
                           ├──> findings/scoring ────> health score + A–F grade
                           └──> renderers ──────────> html / md / json / executive
                                                          │
                                                          └──> history archive (~/.sf)
```

## The org boundary

Every interaction with Salesforce goes through four client interfaces supplied by
`@cclabsnz/sf-core`: `SoqlClient`, `ToolingClient`, `RestClient` and `MetadataClient`. They are
constructed in exactly one place, `src/lib/wire.ts`, which takes a `Connection` from the CLI and
builds an `AuditContext`.

A check never sees the `Connection`. It receives `ctx` and can reach the org only through those
clients. That single seam is what makes the read-only guarantee checkable rather than aspirational —
see [ASSURANCE-CASE.md](ASSURANCE-CASE.md) C1.

`ctx.metadata` is **optional**. `MetadataClient.read()` reads components such as `SecuritySettings`
that SOQL and Tooling do not expose, but it is not always available, so a check must degrade to an
advisory rather than assume it. `login-access-policy` and `session-hardening` are the reference
examples.

## Modules

| Module | Files | Responsibility |
|---|---|---|
| `checks/` | 92 | One class per check implementing `SecurityCheck`, plus the registry and `CheckEngine` |
| `compliance/` | 14 | Sourced control catalogs, `checkId → controlId[]` mapping, framework packs and the provenance gate |
| `chains/` | 5 | Capability model and the named attack chains correlating findings |
| `findings/` | 6 | `Finding` shape, scoring, grade thresholds, per-check effort and impact metadata |
| `renderers/` | 10 | HTML, Markdown, JSON and diff output |
| `report/` | 3 | Executive report composition — priorities, roadmap, compliance matrix |
| `history/` | 4 | Run archive under `~/.sf/audit-history/{orgId}` and the diff engine |
| `timeline/` | 9 | Offline forensic timeline over captured EventLogFile data |
| `apps/` | 8 | Connected-app granted-versus-used analysis |
| `commands/` | 7 | oclif command definitions |
| `lib/` | 2 | The `Connection` → `AuditContext` seam |

## How a check works

A `SecurityCheck` is a class with an `id`, metadata, and `run(ctx): Promise<CheckResult>`. It
inlines its own SOQL — there is deliberately no runtime query registry, since a central catalogue
drifted from the queries it claimed to describe and was removed.

Three contracts constrain a check:

**Read-only.** SOQL, Tooling and REST GETs, and Metadata reads. Enforced statically in CI.

**Report only what you established.** A pass means the analysis completed and found nothing. A
finding means the data supports it. Anything else is `inconclusive`, naming what could not be
evaluated. `CheckEngine` converts permission errors into inconclusive findings rather than letting
them crash the run.

**Declare cache use.** A check declares `dependsOnCache` and `populatesCache`. Ordering in
`registry.ts` is therefore load-bearing: a dependency must be populated by an earlier check, and
`CheckEngine.validateCacheOrdering()` throws at startup if that is violated. This is what keeps 88
checks from re-querying the same Apex bodies or permission sets.

## Correlation

`ChainEngine` runs in two passes. Named chains are hand-modelled scenarios matched on finding ids
and on a capability set derived from `CapabilityRegistry` (finding id → attacker capabilities). An
emergent pass then reports remaining entry-point → outcome pairs that no named chain already
explains, so a novel combination still surfaces at lower confidence.

Both halves address findings by **string id**, and a wrong string fails silently — a registry key
nothing emits never grants; a chain ingredient nothing emits means the chain can never fire.
`registryIntegrity.test.ts` scans the check implementations and fails on either.

## Compliance

Controls live in per-framework catalogs carrying framework, pinned version, official title,
requirement text and a citation. `mapping.ts` maps `checkId → controlId[]` from three layers: a base
per-check map, domain crosswalks (NZ pack, and HIPAA/GDPR) keyed off shared `DOMAIN` groups, and
per-check precise entries where an obligation is narrower than a domain.

A **provenance gate** in `resolve.ts` renders only controls marked `verified`, so an unchecked
citation cannot reach a client report.

## Deliberate constraints

- **ESM throughout, NodeNext.** Relative imports end in `.js` even in `.ts` files.
- **Types are checked separately from tests.** Jest transforms with swc, which strips types without
  checking them, so `npm run typecheck` is the only thing type-checking the test tree and runs ahead
  of Jest in `npm test`.
- **Documentation is test-enforced.** Check counts, the domain summary and the attack-chain list
  fail the build if they drift from the code.
- **Reports are self-contained.** Fonts are embedded as data URIs and Chart.js is inlined from the
  dependency on disk, because a report carrying sensitive findings must not fetch anything when a
  client opens it.

## Dependencies

Runtime: `@cclabsnz/sf-core` (the backbone — check contract, org clients, report helpers),
`@salesforce/sf-plugins-core` and `@oclif/core` (CLI), `@salesforce/core` (the `Connection` type
only), `zod` (scoring config validation), `chart.js` (inlined into history reports).

Design records for individual features live in [`superpowers/specs/`](superpowers/specs/).
