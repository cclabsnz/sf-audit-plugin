# BACKLOG — intents, not tasks

Format: `- [todo] BL-001 (risk) outcome — must-nevers: ...`  Status: todo | running | pr | done | blocked

- [todo] BL-001 (high) `audit incident collect --encrypt` writes the incident bundle encrypted at rest (AES-256-GCM via sf-core's passphrase encryption), and every incident command that reads a bundle refuses an encrypted one without the right passphrase — must-nevers: the passphrase or derived key never reaches stdout, stderr, logs, history or the bundle; no plaintext copy of collected data is left on disk; a wrong passphrase or tampered bundle never yields partial or silently-empty analysis
- [todo] BL-002 (low) mostly shipped as evidence coverage (`src/findings/coverage.ts`, grade capped on a mostly-blind run). Remaining: run the salvaged HARD-04 cases against it and keep only what it misses — must-nevers: an incomplete run never earns a better grade than a complete run of the same org would; skipped checks are never counted as passed
- [todo] BL-003 (medium) decide whether to bring back a validated query registry (per-query required permissions, preflight); the old catalog was removed because it drifted from the checks — must-nevers: a check's SOQL and its registry entry can never disagree unnoticed (single source or a test that fails on drift); no write or DML query is expressible
- [todo] BL-004 (low) a typed catalog of every finding id, checked at compile time against `CAPABILITY_REGISTRY` — must-nevers: a finding id a check emits is never missing from the catalog; does not duplicate what `registryIntegrity.test` already enforces without adding something it cannot

Salvaged drafts for BL-001..004 are on the local branch `salvage/wip-20261016` (see `salvage/README.md` there).
