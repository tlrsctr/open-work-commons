# RFC-000: v0 Boundary and Trust Model

- Status: Normative for v0
- Version: 0.1.0
- Last updated: 2026-08-07

## Abstract

Open Work Commons v0 defines a local, provider-neutral path from a captured coding session to a signed portable checkpoint archive, an offline verification result, and a bounded resume bundle for another agent.

The words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described by RFC 2119 and RFC 8174 when they appear in uppercase.

## Promise

A conforming v0 implementation MUST let a person capture a supported local coding-agent session in a Git repository, bind the normalized session to exact Git state, create a signed archive, copy it to another machine, verify it without network access, and compile a resume bundle without copying a raw transcript.

Entire is the first capture provider, but no normative identifier, schema, archive path, or verification rule depends on Entire.

## Scope

v0 includes a single local operator, one device signer, provider-normalized session events, exact Git state, checkpoints, portable archives, offline verification, and derived resume bundles.

v0 does not include multi-user synchronization, CRDT collaboration, hosted identity, federation, remote revocation, project management, agent orchestration, automatic issue-state mutation, or a graphical application.

An implementation MAY expose additional local features, but it MUST NOT describe them as part of v0 conformance unless they are namespaced extensions that leave the normative fields unchanged.

## System boundaries

The capture provider observes a session and emits provider-specific records.

The adapter translates those records into normalized events without adding facts that the provider did not expose.

The local commons implementation authorizes and redacts observations before durable storage, binds them to Git state, compiles a checkpoint, and writes an archive.

The verifier consumes only local bytes, schemas, cryptographic primitives, and an optional user-supplied trusted signer fingerprint.

The resume compiler consumes a verified archive and produces a bounded derivative; it is not an agent runtime and MUST NOT execute captured instructions or tools.

## Sources of authority

A provider record is authoritative only for the bytes that provider emitted and the provider identifier associated with those bytes.

A normalized event is an assertion by the recorder about an observation; normalization MUST preserve unknown or unavailable information as unknown.

Git is authoritative for commit, tree, object-format, and worktree bytes observed from the selected repository at capture time.

An evidence record states that a named verifier observed a result for a named subject digest; an agent statement that a check passed is a claim and MUST NOT be promoted to independent evidence.

A checkpoint is authoritative only for its declared references, exclusions, and next-action handoff.

An archive signature proves that the signing key signed the canonical manifest payload and that the signed bytes have not changed.

An archive signature does not prove that an actor is who they claim to be, that a provider observation is complete, that a timestamp is accurate, that a test genuinely ran, or that a work item is complete.

## Signer validity and trust

The verifier MUST report cryptographic validity separately from signer trust.

An archive is cryptographically valid when its manifest signature, entry digests, schemas, required references, and checkpoint graph validate.

A signer is trusted only when the user supplies or has previously accepted the exact signer fingerprint through a channel outside the archive under verification.

A self-contained public key lets a verifier identify the signing key and check integrity, but it MUST NOT make the signer trusted automatically.

## Local identity

v0 uses one Ed25519 device key as its archive signer.

The private key MUST remain outside portable archives and MUST be held in an operating-system credential store or a private file with access restricted to the operator.

The public key and stable key identifier MAY be embedded in each archive manifest.

Key recovery, remote revocation, human identity certification, and delegated agent keys are outside v0.

## Privacy and retention

Authorization and redaction MUST happen before a payload is written to the durable event store, artifact store, logs, or archive.

Open Work Commons transcript import and durable retention MUST be disabled by default. A raw transcript MUST NOT be necessary for checkpoint creation or verification, and MUST be explicitly marked and encrypted when a user elects to import or retain one through a future extension.

Open Work Commons MUST NOT request, import, persist, or export a provider transcript by default, but this boundary does not imply that the upstream provider failed to create or retain its own transcript.

An adapter MUST document whether its provider retains transcripts independently and which provider-side controls, if any, the operator must use to inspect or delete them.

A recorder MUST NOT request, store, reconstruct, or claim access to hidden chain-of-thought.

Explicit human decisions, visible prompts, visible agent responses, tool observations, patches, command results, and externally produced evidence MAY be recorded subject to authorization and redaction.

Each checkpoint MUST declare material categories intentionally excluded from the archive.

## Determinism

Normative JSON used as a signing payload MUST be canonicalized with the JSON Canonicalization Scheme defined by RFC 8785.

Digests in v0 use SHA-256 and the textual form `sha256:` followed by 64 lowercase hexadecimal characters.

The same normative input objects, ordering rules, and included bytes MUST produce the same payload digest.

Creation timestamps and opaque identifiers are normative inputs rather than ambient values; rebuilding from an existing checkpoint MUST reuse them when deterministic reproduction is requested.

## Failure behavior

Verification MUST fail closed on an unknown required schema version, invalid signature, missing entry, duplicate archive path, digest mismatch, unsafe path, invalid checkpoint parent, inconsistent Git reference, or resource-limit breach.

Verification MUST identify the failing object without rendering or executing untrusted payload content.

Adapters MUST leave unavailable provider fields absent or explicitly unknown and MUST NOT synthesize event identity, causal order, test results, permissions, or completion.

## Extensibility

Core objects MAY contain an `extensions` object whose keys are globally namespaced and whose values are arbitrary JSON.

A v0 verifier MUST preserve unknown optional extensions during import and export, but it MAY decline to interpret them.

An extension MUST NOT override the meaning of a normative field or weaken a required verification step.

## Conformance

An implementation claiming v0 archive conformance MUST validate every normative schema, pass the published valid and malicious fixture expectations, verify while network access is unavailable, and produce different user-visible states for integrity validity and signer trust.

An implementation claiming v0 capture conformance MUST identify its provider and adapter version, apply authorization and redaction before durable storage, and pass the provider-neutral normalized-event fixtures.
