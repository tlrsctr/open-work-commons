# Open Work Commons v0 Threat Model

- Status: Normative security baseline for v0
- Version: 0.1.0
- Last updated: 2026-08-07

## Security goals

v0 protects the integrity and portable interpretation of a locally captured checkpoint archive while minimizing durable capture of sensitive session material.

The system aims to detect modification, removal, substitution, path manipulation, signer substitution relative to a configured trust anchor, and inconsistent internal references.

The system does not claim that signed statements are true or that a locally compromised machine produced honest observations.

## Protected assets

- Device signing private key.
- Authorized normalized session events.
- Git-state binding and captured patches.
- Checkpoint lineage, exclusions, evidence, and next action.
- Archive manifest, entries, and signature.
- User-supplied trusted signer fingerprints.
- Private source material deliberately excluded from the archive.

## Trust boundaries

Provider output crosses an untrusted adapter boundary before normalization.

Visible agent, tool, repository, and human content crosses an authorization and redaction boundary before durable storage.

Stored events cross a curation boundary when selected for a checkpoint.

Archive bytes cross an untrusted-input boundary when opened on another machine.

Verified archive content crosses a prompt-injection boundary when compiled for a receiving agent.

## Adversaries

### Malicious or compromised capture provider

A provider may omit events, mislabel actors, reorder records, duplicate records, or emit hostile content.

Adapters MUST preserve provider attribution and unknowns, and archive validity MUST NOT be presented as provider completeness.

A provider may independently retain a full transcript even when Open Work Commons does not request, import, persist, or export that transcript; provider-side retention and deletion remain a declared residual risk outside the local archive boundary.

### Malicious archive producer

An archive producer may create internally consistent but false claims or evidence labels.

The UI and verifier MUST distinguish signer identity, claims, provider observations, and independently identified evidence.

### Archive mutator

An attacker may modify, remove, replace, reorder, or append entries after signing.

Signed manifest bytes, entry digests, complete reference resolution, and rejection of unlisted entries control this threat.

### Signer-substitution attacker

An attacker may replace the public key and sign a modified archive with their own key.

Cryptographic validity alone cannot stop this; the verifier MUST compare the resulting key identifier or fingerprint with a local user-supplied trust anchor and report the mismatch distinctly.

### Prompt-injection author

Repository files, provider events, prompts, tool output, artifact text, and next-action source material may contain instructions intended to control a verifier or receiving agent.

The verifier MUST treat all payload content as data, must finish verification before rendering it, and must never execute archive content.

The resume compiler MUST delimit untrusted excerpts, identify their source, and keep compiler policy outside captured content.

### Secret-exfiltration attacker

Prompts, environment values, command output, patches, repository files, or provider logs may contain credentials or personal data.

Authorization, allowlisting, redaction, transcript opt-in, local storage permissions, archive exclusions, and secret-canary tests control this threat.

Redaction after durable storage is insufficient for v0 conformance.

### Archive parser attacker

An attacker may use duplicate JSON keys, deep nesting, huge strings, invalid Unicode, path traversal, absolute paths, symlinks, decompression bombs, excessive entries, or digest-confusion tricks.

The verifier MUST reject duplicate keys, enforce strict UTF-8 and schemas, validate safe paths before extraction, reject special entries, cap resources, and use the digest algorithm declared by the required version rather than attacker-selected code.

### Replay and rollback attacker

An attacker may present an older valid checkpoint as the newest state.

v0 signatures can identify the checkpoint and its parent lineage but cannot discover a newer checkpoint without an external source; user interfaces MUST display archive and checkpoint identifiers and MUST NOT claim freshness.

### False-time attacker

Local clocks and provider timestamps may be incorrect or manipulated.

Event sequence, previous-event links, checkpoint parent references, and content digests determine internal ordering; timestamps remain descriptive.

### Local malware

Malware running as the operator can read authorized inputs, misuse the signing key, alter capture before signing, or tamper with the implementation.

Defending a fully compromised host is outside v0, though operating-system key storage, signed releases, least privilege, and reproducible builds reduce exposure.

## Security invariants

- No verification step requires network access.
- No private signing key appears in an archive.
- No archive becomes trusted solely because its embedded signature validates.
- No raw transcript is required or imported into Open Work Commons durable storage by default.
- No hidden chain-of-thought is requested or persisted.
- No captured payload is executed by verification or resume compilation.
- No unavailable field is inferred as successful, authorized, complete, or true.
- No archive path escapes its root or aliases another path after normalization.
- No decisive resume statement lacks a source reference.

## Retention and deletion

v0 archives are immutable once signed; a correction or reduced archive is a new signed object that MAY reference the superseded archive.

Operators retain operating-system authority to delete the complete local `.owc` store and any archive directories, subject to their own backup and replication choices. The Candidate implementation does not provide selective in-place event deletion because removing one event would invalidate an append-only session chain. Before a Stable release, the project MUST document and test whole-store and whole-archive erasure; selective retention requires a new, explicitly linked checkpoint or store rather than silent history rewriting.

An exclusion records what a checkpoint omitted but is not evidence that all source copies were deleted.

Encrypted optional transcript retention SHOULD use a distinct key so cryptographic erasure does not invalidate the checkpoint archive.

## Required negative tests

- Change one byte of a listed entry.
- Remove a listed entry.
- Add an unlisted file.
- Duplicate a manifest path.
- Replace the embedded public key and signature.
- Change the root checkpoint digest.
- Create a missing or cyclic parent reference.
- Substitute the Git-state file.
- Use `../`, an absolute path, a backslash path, or a symlink entry.
- Use duplicate JSON object keys.
- Exceed each declared resource limit.
- Insert prompt-injection text into a valid payload.
- Insert secret canaries before redaction and assert they do not reach durable files.

## Residual risks

A valid archive may contain lies, biased curation, incomplete history, misleading but correctly attributed evidence, malicious source text, or work produced on a compromised machine.

An upstream capture provider may retain information excluded from the Open Work Commons durable store and archive, so local deletion and archive exclusion do not prove provider-side deletion.

v0 provides portable integrity and explicit provenance boundaries; it does not replace human judgment, independent test reproduction, code review, or endpoint security.
