# Scoring


Each finding is assigned a risk level with a corresponding weight:

| Risk Level | Default Weight |
|------------|---------------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The health score is calculated as `100 - (total weight / max possible weight) * 100`, capped at 0. Passed findings count towards the maximum, so a broad passing audit dilutes real failures; inconclusive and not-assessed findings count towards neither, so a check that gathered no evidence never improves the score.

The audit produces a **Health Score** (0–100) and a **Grade** (A–F):

| Grade | Criteria |
|-------|---------|
| A | Score ≥ 85, no HIGH findings |
| B | Score ≥ 70, ≤ 1 HIGH finding |
| C | Score ≥ 55, ≤ 3 HIGH findings |
| D | Score ≥ 40, no CRITICAL findings |
| F | Score < 40 or any CRITICAL finding |

The HIGH and CRITICAL counts take open findings only (not passed, inconclusive or waived) plus named attack chains. A *potential* chain, inferred from capability overlap rather than matched to a modelled attack, is reported but does not set the grade.

Every output states why the grade is what it is, for example `F: 2 CRITICAL findings (D allows none)` or `C: 2 HIGH findings (B allows at most 1)`.

CRITICAL is kept for breach-grade exposure. An expiring certificate is an outage risk and is rated HIGH. In a sandbox, the admin-count findings (`users-super-admin-combo`, `users-modify-all-data`) are capped at HIGH, with a note to treat them as CRITICAL if the sandbox holds production data. `users-modify-all-data` takes its severity from holders the super-admin finding does not already cover, so the same users are not counted twice. Externally callable Apex is CRITICAL when a class declares `without sharing`, and HIGH when it only lacks a declaration.

## Custom Scoring Config

All weights and grade thresholds are configurable: no recompile needed. This is useful when your org has a different risk appetite (e.g. you want to penalise hardcoded credentials more heavily, or set stricter grade thresholds).

**Step 1:** Copy the sample config as your starting point:

```bash
cp config/scoring.sample.json my-scoring.json
```

**Step 2:** Edit the values. All three sections (`riskScores`, `checkWeights`, `gradeThresholds`) are optional: omit any section to keep the defaults.

```json
{
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  },
  "checkWeights": {
    "hardcoded-credentials": 10,
    "guest-user-access": 10,
    "users-and-admins": 10,
    "apex-sharing": 7
  },
  "gradeThresholds": {
    "A": { "minScore": 90, "maxHigh": 0 },
    "B": { "minScore": 75, "maxHigh": 1 },
    "C": { "minScore": 60, "maxHigh": 3 },
    "D": { "minScore": 40, "maxCritical": 0 },
    "F": {}
  }
}
```

The full list of valid `checkWeights` keys (one per check) is in [`config/scoring.sample.json`](../config/scoring.sample.json).

The config is validated strictly: an unknown or misspelled key is an error, not a silent no-op, and grade thresholds must stay ordered (A at least as strict as B, B as C, C as D) once merged with the defaults. Remove the `_comment` key inside `checkWeights` before use; it is there so the sample cannot be applied unedited. For editor completion, add `"$schema": "https://raw.githubusercontent.com/cclabsnz/sf-audit-plugin/main/schemas/scoring-config.schema.json"`.

**Step 3:** Pass it when running the audit:

```bash
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

Your config is deep-merged with the defaults, so you only need to include the values you want to change.

## Evidence coverage and the grade cap

A clean result only means something if the audit could see the org. Every result carries
`coverage`: `checksRun`, `checksAssessed`, `percent` (rounded down) and the ids of the checks
that gathered no evidence (`notAssessed`). A check is not assessed when every finding it produced
is inconclusive, or when it threw. A check with some evidence and some gaps is assessed; its gaps
show as its own inconclusive findings.

Below 90% coverage a would-be A becomes a B, and `coverage.gradeCapped` is `true`. B, C, D and F
are never changed by coverage. `grade` stays a plain letter, so history, diffs and JSON consumers
are unaffected. To fail a pipeline on any gap, use `--fail-on-inconclusive`.

