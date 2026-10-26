# INT-002 Incident bundles can be encrypted at rest

`sf audit incident collect` writes guest-user event logs, the setup audit trail, login counts
and follow-up user data to a local directory. A consultant's laptop, a synced folder or a handover
drive then holds a client's incident evidence in plaintext. With `--encrypt`, every file in a
sealed bundle is encrypted (AES-256-GCM, via sf-core's `encryptWithPassphrase`), and
`incident report` reads it only with the right passphrase.

Who: the consultant collecting evidence, and whoever the bundle is handed to. Why: incident
evidence is the most sensitive thing this tool writes, and it often leaves the machine it was
collected on.

- MN-004: never write the passphrase, or anything derived from it, to stdout, stderr, logs, history, the bundle, or a report
- MN-005: once `collect --encrypt` finishes, successfully or not, never leave a plaintext copy of collected org data anywhere it wrote (including staged raw logs and `.part` files)
- MN-006: never produce a report, partial or empty, from an encrypted bundle when the passphrase is wrong or any file fails authentication or the manifest hash check
- MN-007: never treat an encrypted bundle as plaintext, or the reverse, without saying so; a bundle is wholly encrypted or wholly not

Out of scope: encrypting report outputs (`incident-report.*`, evidence CSVs), which are
deliverables; key management beyond a passphrase; re-encrypting existing bundles.

Status: agreed 2026-10-26 (RULE-022 and RULE-023 deferred to BL-005)
