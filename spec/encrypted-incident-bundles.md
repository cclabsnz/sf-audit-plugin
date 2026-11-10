# Encrypted incident bundles

Rules for INT-002. Status: agreed 2026-10-26 for RULE-017..021 and RULE-024. RULE-022 (resume)
and RULE-023 (signal handling, stale-staging sweep, free-space pre-check) are deferred to BL-005;
until then RULE-024 refuses any output directory that already holds a bundle.

Terms. *SFEB*: sf-core's encrypted format (scrypt + AES-256-GCM), recognised by the 4-byte `SFEB`
prefix. Bundle files use its chunked version 2 (STREAM construction: each 64 KiB chunk is
authenticated on its own, and the last one is marked, so reordering, truncation and extension all
fail), which is written and read as a stream and never holds a whole file in memory. *Staging area*: a per-run directory, mode 0700, under the incident root
(`~/.sf/incidents/.staging/<run>`), never inside the output directory. *Data query*: any org query
other than resolving the org's identity (`resolveOrgInfo`).

## RULE-017 The passphrase comes only from the environment or a hidden prompt, and never leaves the process
cites: INT-002, MN-004
- When `collect --encrypt` runs, or `report` opens an encrypted bundle
- then the passphrase is read from SF_AUDIT_BUNDLE_PASSPHRASE, else from a hidden interactive prompt when stdin is a TTY (collect asks twice and requires a match), else the command fails naming the env var, before any data query or file write
- and the passphrase is NFC-normalised before use
- and collect rejects a passphrase shorter than 12 characters (report accepts any non-empty one)
- and no command flag accepts the passphrase value, and no command generates one
- and help or error text that explains how to set the env var never shows an inline value (it suggests `read -s`)
- and the passphrase, as raw, hex, base64, UTF-16, URL-encoded or JSON-escaped text, appears in no stdout, stderr, warning, error message, --json result, bundle file or report output; the manifest holds no passphrase hash, verifier or derived key
- When SF_AUDIT_BUNDLE_PASSPHRASE is set and collect runs without `--encrypt`
- then collect warns that the bundle will not be encrypted

## RULE-018 No plaintext byte is ever written inside the output directory of an encrypted run
cites: INT-002, MN-005, MN-007
- When `collect --encrypt` writes any bundle file (filtered logs, anomalies, audit, logins-by-day, follow-up, ip-range copies, and the manifest including every mid-run checkpoint)
- then the content passes through sf-core's encrypting stream before it reaches the file, so the `.part` and the final file both start with the SFEB prefix from their first byte
- and the raw and filtered log plaintext live only in this run's staging area, never in the output directory
- and each file decrypts with the passphrase to the plaintext this run would have written there
- and the decrypted manifest records `encrypted: true`
- and writes use exclusive creation without following symlinks (`wx` / `O_NOFOLLOW`)

## RULE-019 No plaintext org data survives a collect --encrypt run that returns or throws
cites: INT-002, MN-005
- When `collect --encrypt` returns or throws, for any reason (HTTP 401, ENOSPC, the free-space pre-check, a filter error, a checkpoint failure, a follow-up query failure, a refusal)
- then this run's staging area no longer exists, and no file this run created in the output directory is anything but SFEB
- and if removing the staging area fails, the command fails loudly naming the path that still holds plaintext
- and the second pass (actor discovery) and `report` read bundle files through sf-core's decrypting stream and never write a decrypted copy anywhere

## RULE-020 An encrypted bundle is verified in full before any report output exists
cites: INT-002, MN-006
- When `report` reads an encrypted bundle
- then the manifest must decrypt (GCM-authenticated), every listed file must exist, and the sha256 of every listed file's on-disk ciphertext must match the manifest, all before analysis starts
- and the analysis pass hashes the ciphertext again as it streams it; if a chunk fails authentication or the hash at the end of a file differs from the manifest (the file was swapped after the check), report fails as below and nothing is written, because no output is written until analysis has finished
- and a wrong passphrase or a manifest that fails authentication fails with exit 2, saying "wrong passphrase or damaged manifest"
- and a file that fails its hash or authentication fails with exit 2, naming the file
- and in every such case nothing is written: no incident-report.*, no evidence/, and the --output directory is not created if it did not exist

## RULE-021 A bundle is wholly encrypted or wholly plaintext, and the reader always says which
cites: INT-002, MN-007, MN-006
- When `report` opens a bundle, it decides "encrypted" from the manifest's 4-byte SFEB prefix; an SFEB prefix that sf-core cannot read (short, or an unknown version) fails as "unsupported or damaged encrypted bundle", never a JSON parse error
- When the manifest is SFEB, it emits a notice that the bundle is encrypted
- When an encrypted bundle is opened with no passphrase available, it fails saying the bundle is encrypted and how to supply the passphrase
- When a passphrase is available and the bundle is plaintext
- then it warns on stderr that the bundle is not encrypted and the passphrase was not used (it may be a substitution), and reads it as plaintext
- When an encrypted manifest lists any non-SFEB file, or a plaintext manifest lists any SFEB file, or the decrypted manifest's `encrypted` field is not `true` (a plaintext manifest's absent field means false; `true` there is an error)
- then it refuses with exit 2, saying the bundle mixes encrypted and plaintext files, and writes nothing
- and the --json results of collect and report include `encrypted: boolean`

## RULE-022 Resume keeps the bundle's mode and passphrase (deferred to BL-005)
cites: INT-002, MN-005, MN-006, MN-007
- When `collect --encrypt --output <dir>` finds an encrypted manifest (partial or complete) and the passphrase decrypts it
- then logs are reused under the existing conditions (same org id, same guest set, collected status) and only when their ciphertext still matches the recorded hash; newly written files are encrypted under the same passphrase
- When the passphrase does not decrypt the existing manifest
- then collect fails before any data query, saying "wrong passphrase or damaged manifest", and leaves every bundle file in <dir> byte-identical (it never starts fresh over it)
- When `--encrypt` targets a directory holding a plaintext manifest, or collect without `--encrypt` targets one holding an encrypted manifest (partial or complete)
- then it refuses before any data query, naming the bundle's mode, and changes no bundle file in <dir>
- and every collect failure, including these refusals, exits 1 (as collect already does); report failures exit 2

## RULE-023 Plaintext is staged outside the bundle and cleaned up on interrupt and on the next run (deferred to BL-005)
cites: INT-002, MN-005
- When `collect --encrypt` downloads a raw log or filters it
- then the raw and filtered plaintext live only in this run's staging area, never in the output directory
- and SIGINT and SIGTERM remove the staging area before the process exits
- and every collect run, whatever its output directory, first removes staging areas left by runs that are no longer alive, and stray `*.part` files in its own output directory
- and the free-space pre-check counts the raw log, the filtered plaintext and the ciphertext
- Accepted residue: SIGKILL, a crash or power loss can leave a staging area until the next collect run; deleted blocks are not securely erased on APFS or SSDs. Both are stated in the command help.

## RULE-024 Encrypted collection writes only into an empty or new directory
cites: INT-002, MN-005, MN-006, MN-007
- When `collect --encrypt --output <dir>` targets a directory holding any manifest (encrypted or plaintext, partial or complete)
- then it refuses before any data query, saying resume is not yet supported for encrypted bundles, and changes no file in <dir>
- When collect without `--encrypt` targets a directory holding an encrypted manifest
- then it refuses before any data query, saying the bundle is encrypted, and changes no file in <dir>
- When `collect --encrypt --output <dir>` targets a directory that exists, is not empty, and holds no manifest
- then it refuses before any data query, listing the files it did not create, and changes nothing
- and every collect failure, including these refusals, exits 1 (as collect already does); report failures exit 2
