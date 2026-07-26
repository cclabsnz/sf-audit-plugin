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
