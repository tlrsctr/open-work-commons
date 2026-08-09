# RFC-002: Portable Checkpoint Archive

- Status: Normative for v0
- Version: 0.1.0
- Last updated: 2026-08-07

## Abstract

This RFC defines a portable logical archive that binds normalized session events, exact Git state, a checkpoint, optional artifacts, explicit exclusions, and one archive signature.

## Logical layout

A v0 archive contains `archive-manifest.json` at its root and the manifest-listed entries required to resolve its root checkpoint.

Recommended paths are `events/`, `state/`, `checkpoints/`, `artifacts/`, and `evidence/`.

A resume bundle is a verified derivative and SHOULD be stored outside the source archive because embedding the derivative while it cites the manifest payload digest would create a digest cycle.

The conformance fixture uses an unpacked directory as the logical archive representation.

An implementation MAY pack that directory as `.owc.tar.zst`, but the container encoding is not the trust boundary; the signed manifest and exact entry bytes are.

## Path safety

Every manifest entry path MUST be relative, use `/` separators, contain no empty segment, contain no `.` or `..` segment, contain no NUL or backslash, and resolve beneath the archive root after normalization.

Archive entry paths MUST be unique.

Packed archives MUST NOT contain symbolic links, hard links, device nodes, named pipes, sockets, or other special entries.

A verifier MUST check path safety before creating files or reading an entry payload.

## Manifest

The manifest declares the archive format and version, archive identifier, creation time, root checkpoint reference, complete signed entry list, explicit exclusions, resource limits, extensions, and signature metadata.

Every entry declaration contains a safe relative path, media type, semantic role, exact byte length, and SHA-256 digest over the exact stored bytes.

The manifest MUST NOT list itself as an entry.

All entries required by a normative object reference MUST appear in the manifest.

Every entry with role `event`, `git-state`, `checkpoint`, or `evidence` MUST use media type `application/json` and satisfy its locally bundled v0 schema.

Files present in a container but absent from the signed entry list MUST be ignored or rejected and MUST never be exposed to the resume compiler.

## Signature payload

The manifest `signature` object contains the canonicalization algorithm, digest algorithm, signature algorithm, key identifier, raw public key, payload digest, and signature value.

To construct the signing payload, an implementation deep-copies the manifest and removes only `signature.payload_digest` and `signature.value`.

The remaining object is canonicalized using RFC 8785 and encoded as UTF-8 without a byte-order mark.

The `payload_digest` is SHA-256 over those canonical bytes.

The Ed25519 signature is computed directly over those canonical bytes rather than over the textual digest.

The public key uses unpadded base64url encoding of the 32 raw Ed25519 public-key bytes, and the signature uses unpadded base64url encoding of the 64 signature bytes.

The signature binds signer metadata because the key identifier and public key remain in the signing projection.

## Archive construction

A writer MUST authorize and redact observations before selecting archive entries.

A writer MUST serialize each selected object, compute its exact byte length and digest, and then build the complete manifest entry list.

Entries MUST be sorted lexicographically by their path in the manifest.

The root-checkpoint digest MUST match both the referenced checkpoint bytes and the corresponding manifest entry.

The default writer MUST omit raw transcript bytes from the v0 checkpoint and portable archive, and every writer MUST include a `raw-transcript` exclusion describing that boundary.

If a future explicitly authorized extension retains an encrypted transcript copy, it MUST remain outside normative checkpoint and resume inputs, and the exclusion remains required; provider or operator copies outside the archive are unaffected.

The writer then constructs the signing projection, calculates the payload digest, signs the canonical bytes, and writes the completed manifest.

## Verification algorithm

A verifier MUST parse the manifest using a duplicate-key-rejecting JSON parser and validate it against the v0 manifest schema.

A verifier MUST enforce configured limits before expanding or reading untrusted bulk content.

A verifier MUST validate path safety and uniqueness, reject unexpected special entries, and verify that every declared entry exists exactly once with the declared byte length and SHA-256 digest.

A verifier MUST reconstruct the signing projection, verify `signature.payload_digest`, and verify the Ed25519 signature using the embedded public key.

A verifier MUST validate each event, Git-state, checkpoint, and evidence JSON entry against its locally bundled v0 schema.

A verifier MUST resolve the root checkpoint, event references, Git-state reference, artifact references, evidence references, and checkpoint parents without network access.

An inline checkpoint evidence record is complete without a source reference; when `source` is present, the verifier MUST require a manifest entry with role `evidence`, verify its path and digest, and require exact equality of `evidence_id`, `kind`, `issuer`, `subject_digest`, `result`, and `observed_at` between the checkpoint record and evidence object.

A verifier MUST reject a cyclic, missing, or digest-inconsistent checkpoint parent graph.

A verifier MUST report the signer key identifier and fingerprint and separately report whether it matches a user-supplied trust anchor.

A verifier MUST finish all integrity checks before rendering payload text or compiling a resume bundle.

## Git binding

The Git-state object records the repository identifier, Git object format, base commit, head commit and tree, capture time, clean or dirty state, optional patch, and untracked-file declarations.

When `worktree.patch` is present, its entry MUST use media type `application/vnd.openworkcommons.git-patch-v1` and the following binary framing. Multi-byte integers are unsigned and big-endian.

1. the thirteen ASCII bytes `OWC-GIT-PATCH` followed by one NUL byte;
2. one version byte with value `1`;
3. one section-count byte with value `2`;
4. the `index.diff` section; and
5. the `worktree.diff` section.

Each section is encoded as a two-byte UTF-8 name length, the exact UTF-8 section name, an eight-byte payload length, and that many payload bytes. The section order and names are fixed. Trailing bytes, duplicate sections, an unknown version, an unknown name, or a length that does not consume the artifact exactly MUST be rejected.

The `index.diff` payload is the exact output of a local, non-extensible equivalent of `git diff --cached --binary --full-index --no-ext-diff --no-textconv`. The `worktree.diff` payload uses the corresponding worktree comparison without `--cached`. Implementations MUST disable external diff drivers, text conversion, replacement objects, lazy fetching, hooks, pagers, and configured clean, smudge, or process filters for both observations. An implementation that cannot disable a configured content filter MUST fail before running any Git operation that could invoke it. A payload MAY be empty.

The patch entry digest and byte length cover the complete framed artifact, not either section independently. The published vector at `conformance/valid/git-patch-v1.json` fixes the v1 framing independently of any Git installation.

Each untracked declaration uses `path` only as the repository-relative file identity; a verifier MUST NOT resolve that field as an archive entry path. The declaration always binds the exact authorized file bytes with `digest` and `byte_length`, including when the body is omitted.

Untracked declarations MUST be sorted strictly by their UTF-8 path bytes and MUST NOT repeat a repository path. Ignored paths MUST NOT appear. A manifest-only declaration sets `included` to `false` and MUST omit `artifact`; its signed digest and byte length remain the byte commitment even though no file body is present in the archive.

Including an untracked body requires an explicit policy decision, sets `included` to `true`, and requires an `artifact` object containing `path`, `digest`, and `byte_length`. The artifact path MUST equal `artifacts/git/untracked/` followed by the repository-relative path; its digest and byte length MUST exactly equal the declaration's byte commitment. That path MUST resolve to one manifest entry with role `artifact`, media type `application/octet-stream`, and matching exact bytes. The repository-relative `path` and archive-relative `artifact.path` are distinct namespaces even when their suffixes match.

Git does not expose an atomic worktree snapshot. A writer MUST therefore compare two complete local observations and fail if the repository identity, refs, index, tracked patch bytes, untracked path set, or bound untracked bytes differ. This narrows but does not eliminate filesystem races; consumers MUST treat `captured_at` as an observation time rather than proof of an atomic filesystem state.

When repository bytes are available and the operator requests a comparison, a verifier SHOULD independently recapture the declared base, head, tree, tracked patch, and untracked commitments without fetching or executing repository-configured filters. It MUST report `matched`, `mismatched`, or `unavailable` separately from the archive's internal integrity and signer trust.

The pure logical-archive verifier accepts no filesystem authority and therefore reports `externalRepositoryVerification: { "status": "not-checked" }` on successful and failed internal verification. The reference CLI's optional `--repo` boundary runs only after internal integrity and the explicit signer policy succeed, then replaces that field with the bounded external result. A requested mismatch or unavailable comparison MUST be non-zero but MUST NOT retroactively label the signed archive bytes internally invalid.

An archive without repository bytes can still be internally valid when the Git-state entry digest validates, but the verifier MUST NOT claim that an external repository matches it.

## Resume bundles

A resume compiler MUST require a valid source archive.

A resume bundle cites the source archive payload digest, signer key identifier, checkpoint digest, bounded source list, objective, constraints, Git state, decisions, evidence, evidence gaps, open questions, exclusions, and exact next action.

Captured payload text is untrusted data and MUST be delimited from compiler instructions.

A resume compiler MUST NOT execute tool calls, shell fragments, links, or instructions discovered in archive content.

Every decisive statement in a resume bundle MUST cite one or more source entries by path and digest.

The compiler MUST record its item and UTF-8 byte budgets and all material excluded because of policy or budget.

For a `json-and-markdown` bundle, `max_utf8_bytes` is one shared upper bound applied independently to the complete JSON serialization and the complete Markdown serialization. Complete means all source identity, budget metadata, policy text, citations, source entries, delimiters, and material-omission reporting; implementations MUST NOT measure only a payload subsection. The v0 reference JSON serialization uses two-space indentation and one trailing LF, and the Markdown serialization uses one trailing LF.

`actual_utf8_bytes` MUST equal the larger exact UTF-8 byte length of those two complete serializations. Because each serialization contains `actual_utf8_bytes`, a compiler MUST resolve the resulting byte-count fixed point before returning output and MUST fail closed if it does not stabilize. An implementation MUST remove optional items in its documented deterministic priority order until both serializations fit. It MUST fail rather than truncate a mandatory objective, constraint, exact Git state, exclusion, next action, citation, source or omission record, string, or UTF-8 code point.

## Offline operation

Schema resolution for v0 verification MUST use local bundled schemas even when their `$id` values are HTTPS identifiers.

A verifier MUST NOT perform DNS resolution, network key discovery, timestamp lookup, certificate lookup, provider API calls, model calls, or telemetry during verification.

Trust anchors MUST be supplied locally.

## Limits

A verifier MUST apply limits for packed bytes, expanded bytes, entry count, individual entry bytes, JSON nesting, and JSON string length.

The manifest fixture values are not universal defaults; implementations MAY apply smaller limits and MUST reject rather than partially verify an archive that exceeds them.

## Forward compatibility

A v0 verifier MUST reject an unknown required archive version.

It MUST preserve optional namespaced extensions when importing and exporting an otherwise valid archive.

It MUST reject an extension that attempts to replace a normative digest, signature, path, authority, or verification rule.

## v0 compatibility note

A pre-release manifest entry already labeled with role `evidence` now has normative JSON semantics and MUST migrate to the v0 evidence schema or use a non-normative role that accurately describes its content.

Inline-only checkpoint evidence remains valid, while an existing `source` reference that points to an artifact or extension entry MUST migrate to a matching role-`evidence` JSON object.
