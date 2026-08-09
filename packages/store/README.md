# OWC private local store

This package is the v0 filesystem store for authorized normalized events and exact artifact bytes inside one local workspace.

It is intentionally not a database, sync engine, archive, transcript recorder, or source of truth about whether a provider observation is true.

## Boundary

`LocalWorkspaceStore.initialize(workspacePath, { policy })` creates a private `.owc` directory, and `LocalWorkspaceStore.open(workspacePath, { policy })` reopens the same format without network access.

There is no permissive default policy: every caller must inject blob authorization/redaction, event authorization/redaction, and read authorization.

Policy denial, malformed policy output, and policy exceptions fail closed with fixed diagnostics that never include rejected bytes or event content.

Blob and event inputs are bounded before policy evaluation, policy-authorized results are bounded again, and no write lock, temporary file, content directory, or final content file is created until policy evaluation succeeds.

Raw transcripts remain out of scope and should be denied unless a future explicit encrypted extension defines their lifecycle.

## Layout

```text
.owc/
  format.json
  device/ # optional opaque subtree owned and validated by the identity package
  events/<sha256(event-id)>-<sha256(canonical-event-bytes)>.json
  blobs/sha256/<first-two-hex>/<remaining-hex>
```

Opaque event and session identifiers never become path segments, and event filenames bind both the hashed event identity and the digest of the canonical event bytes.

Blob digests cover the exact bytes returned by the policy, not the proposed bytes presented to it.

The local-file adapter deliberately refuses Windows and any runtime without an effective POSIX user identifier or no-follow file opening; this is safer than claiming privacy on a platform where the adapter cannot enforce it.

Every directory boundary must be owned by the effective user with exact mode `0700`, and every file must be owned by that user with exact mode `0600` and one link; weak modes, foreign owners, symlinks, hard links, and special entries fail closed before content is read or reused.

The optional top-level `device` directory is accepted as an opaque co-owned boundary after the store verifies that directory's owner, mode, and type; only the identity package traverses and validates its private contents, and all other unexpected `.owc` root entries are rejected.

## Write behavior

`putBlob` content-addresses authorized bytes and returns `stored` or `existing` for an identical replay.

`appendEvent` validates the v0 normalized event shape, verifies inline payload digests or local blob references, enforces contiguous per-session sequence and previous-event links, and returns `stored` or `existing` for an identical replay.

Event timestamps use a deliberately strict RFC 3339 lexical subset with uppercase `T`, uppercase `Z` or a colonized numeric offset, plus Ajv-full-compatible calendar, timezone-boundary, and leap-second semantics; impossible dates and normalized `Date.parse` rollovers are rejected.

Event types are limited to the eight v0 core values or an explicit `<reverse-dns>/<dotted-type>` extension so an unknown unnamespaced observation cannot silently acquire core meaning.

The same event identifier with different canonical bytes or a different digest is an immutable conflict.

Each file is written to a same-directory unpredictable temporary file with exclusive creation and `0600` mode, flushed with `fsync`, atomically published without replacement through a same-filesystem link, reduced back to exactly one link before success, and followed by a parent-directory `fsync` where the platform supports it.

`readBlob` and `readEvent` authorize before reading and then revalidate content-address bindings; `healthCheck` reads only local bytes and returns fixed structural issue codes without rendering captured content.

## Crash and locking limits

Writers coordinate through `.owc/write.lock`, which is an exclusive advisory lock file for cooperating OWC processes rather than an operating-system lease.

A killed process can leave a stale lock or a same-directory `.tmp-*` file; health check reports both conditions, and an operator must confirm that no writer is alive before removing them.

A non-cooperating process with the operator's filesystem privileges can ignore the advisory lock or replace local bytes, although digest-derived event and blob paths let health check detect replacement that does not preserve the expected digest.

An individual event or blob write is crash-atomic at the link publication boundary; interruption between publication and temporary-link removal leaves a detectable hard-link condition that every reader refuses, while a blob followed by a referring event is not a multi-file transaction, so an unreferenced blob can remain after interruption.

Directory `fsync` is best effort on platforms that reject directory handles, and power-loss guarantees ultimately depend on the host filesystem and storage device.

There is no automatic stale-lock recovery, cross-host locking, compaction, garbage collection, selective event deletion, migration, or concurrent snapshot isolation in this slice. A person can erase the complete local store with ordinary operating-system file controls, but the pre-alpha CLI does not yet wrap or attest that destructive operation.

## Default limits

The defaults are 16 MiB per blob, 1 MiB per event, JSON depth 64, 512 KiB per JSON string, 100,000 events, 100,000 blobs, and 100 returned health issues.

Callers may lower limits when opening the store, and limit violations reject the operation rather than partially reading or writing an object.
