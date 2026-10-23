# Remediation roadmap

## RULE-073 The roadmap holds only open, assessed findings rated LOW or above
cites: INT-013, MN-057
- When the roadmap is built
- then INFO findings (inventories, advisories) and not-assessed findings (a check that failed or gathered no evidence) are left out, as are passed, inconclusive and waived ones
- and they remain in the findings appendix and the coverage line

## RULE-074 A healthy result is reported as passed, not as an open LOW finding
cites: INT-013, MN-057
- When a check's measure falls in its lowest band
- then the finding is `passed`, keeping its id, title and affected items: `failed-logins` with 20 or fewer failures, `health-check-score` of 85 or more, `users-modify-all-data` rated LOW, `users-view-all-data` with 5 or fewer holders
- and `users-modify-all-data` and `users-view-all-data` still take part in attack-chain correlation while they list any holder: a healthy count is still someone who holds the power
