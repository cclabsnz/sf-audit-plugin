# Command reference

Full flag reference for every command. The [README](../README.md) covers the common path, what the
audit covers, the compliance mapping and the attack chains.

- [`sf audit security`](#sf-audit-security) — every flag, examples, and the executive report
- [Free event baseline](#free-event-baseline) — `sf audit events pull`
- [Forensic timeline](#forensic-timeline) — `sf audit timeline`
- [History and diff](#history--diff) — `sf audit history`, `sf audit diff`
- [Connected-app least-privilege](#connected-app-least-privilege) — `sf audit apps`

---

## `sf audit security`

The audit itself. The [README](../README.md#usage) covers the common path; this is the full flag set.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target-org` | *(required)* | Org alias or username to audit |
| `--format` / `-f` | `html` | Output format(s), comma-separated: `html`, `md`, `json`, `executive` |
| `--output` / `-o` | `.` | Directory to write the report file |
| `--fail-on` | (none) | Exit with code 1 if any finding is at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--checks` | *(all)* | Comma-separated check IDs to run instead of all 88 (e.g. `hardcoded-credentials,apex-sharing`) |
| `--scoring-config` | (none) | Path to a custom scoring config JSON file to override weights and grade thresholds |
| `--prepared-for` | (none) | Client name for the executive report cover line |
| `--branding` | (none) | Path to a `report-branding.json` to override CloudCounsel defaults (executive format) |
| `--top` | `5` | Number of executive priorities to highlight (executive format) |
| `--frameworks` | `universal` | Compliance matrix scope (executive format): `universal` (OWASP/OWASP LLM/SOC 2/ISO 27001), `nz` (ISO/HISO/Privacy Act/NZISM), `all`, or a comma list (e.g. `owasp,owasp-llm,iso,nzism`, or `hipaa` / `gdpr` for a US healthcare or EU/UK engagement) |
| `--resolve-domains` | `false` | Makes **outbound DNS queries from this machine** to verify CSP trusted domains still resolve (flags unresolvable / parked domains as exfiltration channels). Off by default; a default run contacts **only the target org** and never reaches out to any other host. |

### Examples

```bash
# HTML report (default)
sf audit security --target-org myOrg

# Multiple formats at once
sf audit security --target-org myOrg --format html,md,json

# Write report to a specific directory
sf audit security --target-org myOrg --output ./reports

# Fail CI pipeline on HIGH or CRITICAL findings
sf audit security --target-org myOrg --fail-on HIGH

# Run only specific checks
sf audit security --target-org myOrg --checks hardcoded-credentials,apex-sharing,guest-user-access

# Guest / Experience Cloud exposure sweep — the unauthenticated data-leak surface
# (bulk-read via UI API, guest-owned records defeating Private OWD, file access, self-reg, threat detection)
sf audit security --target-org myOrg --checks guest-user-access,guest-object-exposure,guest-site-options,guest-executable-apex,experience-cloud-site,threat-detection

# Use a custom scoring config (e.g. stricter weights for your org)
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

### Executive report

`--format executive` produces a CloudCounsel-branded, print-to-PDF HTML report for clients:
grade and executive summary, top priorities with abuse/impact narratives, attack scenarios, a
risk×effort remediation roadmap, and a **compliance coverage matrix** mapping findings to framework
controls. It is fully self-contained (fonts embedded); open it and **Save as PDF**.

```bash
# Branded executive report for a client (universal compliance matrix)
sf audit security --target-org myOrg --format executive --prepared-for "Acme Health" --top 5

# NZ health/government engagement: NZ framework matrix
sf audit security --target-org myOrg --format executive --frameworks nz

# White-label / co-brand via overrides
sf audit security --target-org myOrg --format executive --branding ./report-branding.json
```

Compliance controls are mapped from authoritative, version-pinned sources (OWASP Top 10:2021,
OWASP Top 10 for LLM Applications 2025, AICPA TSC, ISO/IEC 27001:2022, the Security Benchmark for
Salesforce, NZ Privacy Act, HISO 10029, NZISM, 45 CFR Part 164 Subpart C, Regulation (EU)
2016/679). Only source-verified controls render. "No findings detected" is **not** an attestation of
compliance (see the report's Scope & Liability section).

The report file is written as `sf-audit-<orgId>-<timestamp>.<ext>` in the output directory (e.g. `sf-audit-00D000000000001-1711234567890.html`).

---

# Free event baseline

Salesforce's free tier exposes **Daily-interval `EventLogFile` logs** (login, API, and error
activity) on Enterprise/Unlimited/Performance editions and Developer Edition — *without* the paid
Event Monitoring / Shield add-on. The catch: on the free tier those logs are retained for only
**~1 day**. Miss a day and that day's activity is gone.

`sf audit events pull` captures them to local disk before they expire, so a daily run builds a
rolling local baseline you own:

```bash
sf audit events pull --target-org myOrg
```

It queries whatever daily event types the org actually exposes, downloads each log's CSV body, and
saves it to `~/.sf/event-baseline/{orgId}/{EventType}/{LogDate}-{Id}.csv`, plus a per-run manifest.
It is **read-only** (GET only) and **idempotent**: any log already on disk is skipped, so it is safe
to run repeatedly. Run it once a day from cron or a scheduled GitHub Action and you beat the 1-day
retention window with a growing archive — no add-on required.

```bash
# Daily cron entry (07:15) — capture yesterday's logs
15 7 * * *  sf audit events pull --target-org myOrg >> ~/.sf/event-baseline/pull.log 2>&1
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--since` | Days of `LogDate` to request (`LAST_N_DAYS` window) | `1` |
| `--types` | Restrict to specific EventTypes, comma-separated (e.g. `Login,ApiTotalUsage`) | *(all available)* |
| `--output` / `-o` | Base directory to store logs under | `~/.sf/event-baseline` |

```bash
# Backfill the last 3 days (each still subject to the org's retention)
sf audit events pull --target-org myOrg --since 3

# Only pull login and API-usage logs
sf audit events pull --target-org myOrg --types Login,ApiTotalUsage

# Store under a project-local directory instead of ~/.sf
sf audit events pull --target-org myOrg --output ./event-baseline
```

> Reading `EventLogFile` requires the **View Event Log Files** permission on the running user (this
> is in addition to the minimum read-only audit permission set). If it is missing, or the edition
> does not expose free daily logs, the command exits cleanly with an explanation rather than failing.

**Example output:**

```
Pulling free EventLogFile logs for org: My Org (00D000000000001)

─────────────────────────────
  Event Baseline Pull
─────────────────────────────
  Found           7
  Downloaded      7
  Skipped         0  (already saved)
  Total bytes  48213
─────────────────────────────
  Saved to: ~/.sf/event-baseline/00D000000000001
  Manifest: ~/.sf/event-baseline/00D000000000001/_manifests/manifest-...-....json
```

## Analyzing the captured logs

`events pull` is the collection half. To triage those `EventLogFile` CSVs for exploit and
abuse patterns, use the companion CLI **[sfelf-triage](https://github.com/cclabsnz/sfelf-triage)**.
It reads downloaded EventLogFile CSVs and emits a per-IP verdict
(`BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE`), answering *"is this guest/community IP a
vulnerability scanner or a real threat?"* — with **zero network egress** and no org connection.

sfelf-triage reads this plugin's `~/.sf/event-baseline/<orgId>` layout directly, so the two
tools chain with no glue:

```bash
sf audit events pull --target-org myOrg          # capture (this plugin)
sfelf-triage analyze ~/.sf/event-baseline/<orgId>  # triage (companion)
```

See the [sfelf-triage README](https://github.com/cclabsnz/sfelf-triage#readme) for install and usage.

---

# Forensic timeline

Salesforce splits one actor's activity across many event types, and each carries a different
subset of identifying fields — so no single log answers *"what did this actor do"*. Filtering by
IP finds the requests but misses every SOQL execution, because the query log has no `CLIENT_IP`
column at all. Filtering by user finds everything the *guest* user did, which on a community is
everyone.

`sf audit timeline` correlates a seed across every captured event type and writes a defensible
timeline:

```bash
sf audit timeline --window 2026-08-02T04:00Z/PT1H --seed ip:203.0.113.50
```

It runs **entirely offline** against captures written by `sf audit events pull` — no org
connection is opened, so it still works long after the org's retention window has expired or its
credentials have been revoked. The org id is inferred from the capture directory when only one
org has been captured.

## What it will not do

Cross-event correlation is easy to get confidently wrong, and a wrong answer here reads as
evidence. Two rules are enforced and both are visible in the output:

- **A blank field is never a join key.** A blank `REQUEST_ID` used as a key stops identifying
  anything and starts matching every other row whose value is also blank — quietly attributing
  strangers' sessions to your actor.
- **A shared identity is not expanded.** A community guest user can stand for hundreds of
  distinct visitors. Expanding through it would present the whole crowd's activity as one
  actor's, so it is refused by default and the refusal is reported with its evidence:

  ```
  Expansion refused: userId 005xx0000000000 is shared by 1371 distinct addresses
    (threshold 8). Override with --allow-shared-identity.
  ```

Every output also leads with what was actually captured, because *"no rows matched"* means two
entirely different things — the actor did nothing, or nobody captured the hour they did it in:

```
Window — coverage INCOMPLETE
  captured   AuraRequest, ListViewEvent
  MISSING    LightningInteraction (not-in-core-set)
  MISSING    GuestUserAnomalyEventStore (storage-disabled)

No activity in captured sources. Coverage incomplete — 2 sources missing.
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--window` | When to look — see below | required |
| `--seed` | Typed and repeatable: `ip:` `user:` `session:` `request:` `login:` `transaction:` `event:` | *(whole window)* |
| `--org-id` | Which captured org to read | *(inferred when unambiguous)* |
| `--input` | Capture base directory | `~/.sf/event-baseline` |
| `--allow-shared-identity` | Expand through identities shared by many actors | `false` |
| `--max-cardinality` | Distinct-actor ceiling above which a key is not expanded | `8` |
| `--format` | Comma-separated: `csv,json,md` | all three |
| `--output` | Directory to write into | `.` |

**Finding your way in.** Two things you do not have to know up front. Omit `--seed` and you get
the whole window, uncorrelated — which is where you look to find something worth seeding on.
Ask for a window that was never captured and the error lists the days that *were*:

```
No captures for 2026-07-01 under ~/.sf/event-baseline/00Dxx0000000000EAA.

Captured days for this org:
  2026-08-01   11 event type(s), whole day
  2026-08-02   14 event type(s), whole day

Try:  --window 2026-08-02
```

**Saying when.** `--window` takes whichever form is nearest to hand — you should not have to
compose an ISO 8601 interval while an incident is running:

| You type | You get |
|---|---|
| `yesterday` | the whole of yesterday, UTC |
| `today` | midnight UTC until now |
| `2h` · `90m` | the last two hours; the last ninety minutes |
| `2026-08-02` | that whole day — the shape the free tier captures in |
| `2026-08-02T04:17Z` | the hour containing that instant, for a timestamp pasted from an alert |
| `2026-08-02T04:00Z/PT1H` | an exact interval, start and duration |
| `2026-08-02T04:00Z/2026-08-02T06:00Z` | an exact interval, start and end |

Times are UTC, because every capture is stored in UTC — a bare timestamp with no zone is read
that way rather than as local time. A window has to fall inside one UTC day; one that crosses
midnight is refused, and the error names the two runs that would cover it.

```bash
# Follow one address across every captured event type
sf audit timeline --window yesterday --seed ip:203.0.113.50

# Start from a request and walk outward, including its Apex cascade
sf audit timeline --window 2026-08-02T04:00Z/PT1H --seed request:abc123

# Several orgs captured — name the one to read
sf audit timeline --org-id 00Dxx0000000000EAA --window 2026-08-02T04:00Z/PT2H --seed user:005xx000000000

# Machine-readable only, into an evidence directory
sf audit timeline --window 2026-08-02T04:00Z/PT1H --seed ip:203.0.113.50 \
  --format json --output ./evidence/incident-2026-08-02
```

**Outputs:**

| File | Contents |
|------|----------|
| `timeline.csv` | The correlated rows, one schema across all sources, chronological |
| `timeline.json` | The same rows plus the provenance — seeds, every key expanded through, and every refusal |
| `summary.md` | Narrative: coverage, per-type counts, what tied each row in, refusals, and whether records left |

Each row records **which join key tied it in**, so attribution is checkable rather than asserted.
The `rows_processed` and `records_returned` columns are populated only from Real-Time Event
objects — no `EventLogFile` type records them — and when none were captured the summary says the
question is unanswerable rather than going quiet, since silence there reads as *"nothing left"*.

## Checking a claim against its control group

When a seed's rows share an identity with many other people — a community guest user, a shared
integration account — *"this actor did X"* needs something to be checked against. Otherwise the
claim is unfalsifiable: nobody can tell your 15 rows from the other 600 behind the same user.

The refusal message already gives you the denominator:

```
Expansion refused: userId 005xx000000000 is shared by 1371 distinct addresses (threshold 8).
```

To see the peer set itself, run the command a second time seeded on that identity, with expansion
allowed:

```bash
# 1. The claim — narrow, seeded on something that identifies one actor
sf audit timeline --window 2026-08-02T04:00Z/PT1H --seed request:REQ000000 \
  --output ./evidence/actor

# 2. The control — everyone behind the identity those rows share
sf audit timeline --window 2026-08-02T04:00Z/PT1H --seed user:005xx000000000 \
  --allow-shared-identity --output ./evidence/peers
```

Both use the same schema, so they concatenate and diff directly:

```bash
# How much of the identity's activity is actually your actor?
# (tail -n +2 skips the header row, so these are data rows)
echo "actor:   $(tail -n +2 ./evidence/actor/timeline.csv | wc -l)"
echo "control: $(tail -n +2 ./evidence/peers/timeline.csv | wc -l)"
```

An actor accounting for 15 of 603 rows — 2.5%, and separable by request id — is a different
finding from one accounting for 580 of 603. The second command is what lets a reviewer tell
which they are looking at, rather than taking the first on trust.

> `sf audit timeline` adds **no checks** and does not affect the security grade. It is an
> investigation command, not a `SecurityCheck`.

---

# History & Diff

Every `sf audit security` run automatically archives a JSON copy of the report to:

```
~/.sf/audit-history/{orgId}/sf-audit-{orgId}-{timestamp}.json
```

No configuration needed: archiving happens silently after each run.

## View Audit History

Show how your org's security posture has changed across multiple runs:

```bash
sf audit history --target-org myOrg
```

Prints a terminal table with score trends and writes an HTML timeline to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--reports-dir` | Custom directory containing archived reports | `~/.sf/audit-history/{orgId}` |
| `--output` | Directory to write the HTML timeline | `.` (cwd) |
| `--limit` | Maximum number of most-recent runs to show | all |

**Example output:**

```
Audit History: My Org (00D000000000001)
────────────────────────────────────────────────────────────────────────────────
  #   Date                  Score   Grade   CRIT   HIGH    MED    LOW   Δ Score
────────────────────────────────────────────────────────────────────────────────
   1  2026-03-23 15:10       64      D          1      5      8      3        —
   2  2026-04-09 11:22       81      B          0      2      5      3      +17
────────────────────────────────────────────────────────────────────────────────
  Trend: ▲ +17 over 2 audits   Best: 81 (2026-04-09 11:22)   Worst: 64 (2026-03-23 15:10)
```

## Diff Two Reports

Compare any two audit JSON files to see exactly what changed:

```bash
sf audit diff baseline.json current.json
```

Writes an HTML and JSON diff report to the current directory.

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--output` | Directory to write diff reports | `.` (cwd) |
| `--format` | Comma-separated formats: `html`, `json` | `html,json` |

**Example output:**

```
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....html
Diff report written: ./sf-audit-diff-00D000000000001-...-vs-....json

─────────────────────────────
  Diff Summary
─────────────────────────────
  Score delta     +17
  Grade        D → B
  New               0
  Resolved          1
─────────────────────────────
```

---

# Connected-app least-privilege

Connected-app over-privilege was at the centre of the 2025-2026 wave of Salesforce data-theft
via OAuth: apps authorized with more scope than they use, and integration users with far more
object access than the app ever touches. The static checks (`connected-apps`, `connected-app-scope`,
`connected-app-inactivity`) tell you what was *granted*. `sf audit apps` tells you what is actually
*used*, so it can point at the specific access to remove.

```bash
sf audit apps --target-org myOrg --since 7
```

It reads the `RestApi` `EventLogFile` to see which objects each connected app touched, compares that
against the objects its run-as user can reach, and reports the over-grant per object and read/write
bit — plus a generated least-privilege permission set granting exactly what was observed. App IDs are
resolved to human-readable names (`AppMenuItem` / `ConnectedApplication` / a bundled standard-app
catalog / `LoginHistory` correlation), and anything unresolved is flagged loudly rather than hidden.

It is **read-only**: the suggested permission set is emitted as data, never deployed.

**Honest bounds.** `RestApi` attributes roughly half of API traffic to a connected app (the rest is
UI-API / session traffic), so *used* is a lower bound. Findings carry the observation window and
attribution rate, and revoke recommendations are suppressed below a soak window and for apps used by
many interactive users. Reading `EventLogFile` needs the **View Event Log Files** permission (the same
one `events pull` uses).

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-org` | Org alias or username | required |
| `--since` | Days of `RestApi` log to analyze | `7` |
| `--from` | Read `RestApi` CSVs from a local `events pull` baseline dir instead of downloading | *(download)* |
| `--soak` | Minimum window (days) before asserting revoke recommendations | `7` |
| `--format` | `table` / `json` / `md` | `table` |

```bash
# Reuse an events-pull baseline instead of downloading again
sf audit apps --target-org myOrg --from ~/.sf/event-baseline/00Dxxx

# Machine-readable output
sf audit apps --target-org myOrg --format json
```
