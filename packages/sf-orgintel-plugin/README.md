# @cclabsnz/sf-orgintel

> Understand how a Salesforce org actually works — its processes, people, and couplings — from metadata and behavioral data, entirely locally.

A read-only `sf` CLI plugin that analyses an org's metadata and behavioural tables to reveal
how it is actually used. Where a security audit answers *"how secure is this org,"* OrgIntel
answers *"how does this org work."*

**Local-first and deterministic by design.** No metadata ever leaves your machine: the only
network calls are to the authenticated Salesforce org's APIs. No LLM/AI calls, no telemetry,
no analytics. Same org in, same findings out.

## Commands

| Command | Answers |
| --- | --- |
| `sf intel probe` | *What can this org tell us about itself?* — a capability & evidence-coverage probe. |
| `sf intel discover` | *Where do this org's business processes live?* — anchor-object ranking + domain fingerprint. |
| `sf intel map` | *Which objects are coupled into cross-cutting processes, and by what automation?* |

Every command supports `--json` (machine output) and `--target-org` per `sf` convention, and
is strictly read-only against the org (SOQL / Tooling / Metadata reads and describes only).

## Install (local dev)

```
pnpm -r build
sf plugins link packages/sf-orgintel-plugin
sf intel probe --target-org <alias>
```

## Trust & verification

The two claims at the top of this README — strictly read-only, and local-first — are enforced
as tests, not asserted in prose:

- **Read-only.** `test/unit/invariants/readonly-invariant.test.ts` statically scans this
  package's entire source tree and fails the build if any jsforce mutation API, HTTP write
  verb, or bulk/composite write path appears. All org I/O funnels through the
  `@cclabsnz/sf-core` clients (SOQL / Tooling / REST **GET** / Metadata reads only); this
  package issues no direct network calls of its own.
- **Local-first.** `test/unit/invariants/network-egress.test.ts` fails the build on any
  third-party HTTP client, raw `node:http`/`https` use, telemetry/analytics/LLM endpoint,
  websocket, or remote asset in a generated report. No metadata leaves your machine: the
  only network destination is the org you authenticated against. No LLM/AI calls, no
  telemetry, no analytics.

Run both yourself:

```
pnpm --filter @cclabsnz/sf-orgintel test test/unit/invariants
```

Analysis is also **deterministic** — same org in, same findings out — and cached under
`~/.orgintel/cache/<orgId>` keyed by a content hash of the component analysed, so the cache
is a pure memo and never changes a result.
