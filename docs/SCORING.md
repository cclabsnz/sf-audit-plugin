# Scoring


Each finding is assigned a risk level with a corresponding weight:

| Risk Level | Default Weight |
|------------|---------------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The health score is calculated as `100 - (total weight / max possible weight) * 100`, capped at 0.

The audit produces a **Health Score** (0–100) and a **Grade** (A–F):

| Grade | Criteria |
|-------|---------|
| A | Score ≥ 85, no HIGH findings |
| B | Score ≥ 70, ≤ 1 HIGH finding |
| C | Score ≥ 55, ≤ 3 HIGH findings |
| D | Score ≥ 40, no CRITICAL findings |
| F | Score < 40 or any CRITICAL finding |

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

**Step 3:** Pass it when running the audit:

```bash
sf audit security --target-org myOrg --scoring-config ./my-scoring.json
```

Your config is deep-merged with the defaults, so you only need to include the values you want to change.
