# OWC approved handoff core

This package implements the first executable Entire-backed portable handoff as a two-phase, provider-neutral library.

The package never invokes Entire, Git, a model, a network, or a tool; the caller must supply sanitized Entire 0.9 checkpoint-detail JSON, a previously captured exact Git state, an operator-authored plan, an explicit RFC 3339 capture time, and a device signing capability.

## Public API

`inspectHandoff(input)` is a pure review phase that validates the strict plan and exact Git bytes, runs only the bounded caller-supplied Entire importer, derives stable content identities, and returns the complete proposed events, checkpoint, Git/artifact descriptors, minimal provider projection, exclusions, residual gaps, proposed archive descriptors, proposed signed-payload digest, and one canonical approval digest.

Inspection reads only `signingIdentity.publicIdentity`; it does not call `sign`, `createSignedArchive`, or any persistence method.

`createApprovedHandoff({ ...input, approvalDigest })` recomputes the entire inspection, compares the exact digest before signing, constructs one `human.intervened` event for each explicit decision plus a terminal `checkpoint.requested` event, creates the exact signed logical archive through the capability, and independently verifies that the signer and every output byte match the reviewed proposal.

`createExactHandoffStorePolicy(storeWritePlan)` first reconstructs and re-verifies the signed archive represented by the plan, then returns a fail-closed local-store policy that allows only those exact archive bytes and normalized events, denies transformations and all reads, and permits identical replay for crash recovery.

`persistApprovedHandoff(store, storeWritePlan)` writes approved blobs first and events in their exact chain order, checks every returned digest and identity, and can be retried idempotently after interruption when the store uses the exact policy above.

## Truth boundary

The operator plan is recursively exact-keyed, bounded by UTF-8 bytes and list counts, required to already be NFC, free of Unicode control, format, bidirectional, line-separator, and paragraph-separator characters, and binds the expected provider, Entire 0.9 version, external checkpoint identifier, human actor, space, work definition, decisions, open questions, next action, sensitivity, and retention.

An absent or empty decision list is valid and produces only the terminal `checkpoint.requested` event; each ordered decision produces exactly one preceding `human.intervened` event, so decision content, count, and order are approval-bound.

Capture and expiry times use the same strict lexical and calendar policy as the archive and local-store validators: four-digit years including `0000`, uppercase `T`, uppercase `Z` or a colonized numeric offset, real Gregorian dates, and fractional seconds within the 128-character timestamp bound.

A seconds value from `60` through strictly less than `61` is accepted only when the represented local time maps to the UTC `23:59` leap-second boundary under the archive/store policy; the package does not claim that a leap second was historically scheduled on that date, and it does not normalize equivalent offsets to one spelling.

The allowlisted provider projection contains only provider/checkpoint identity, provider timestamp, external session identifiers, session indexes and timestamps, metadata-availability flags, and imported gap codes.

Provider messages, summaries, intent, outcome, friction, open items, learnings, reported file lists, model metadata, token counts, transcript, prompts, responses, hidden reasoning, and unknown fields never enter the inspection or archive.

Provider event history and order are not reconstructed; every normalized event is explicitly marked operator-authored, the checkpoint has no invented parents, claims, evidence, completion state, or test result, and all imported gap codes remain visible in namespaced extensions.

The same normalized plan, minimal provider projection, exact Git state and artifact-byte digests, capture time, exclusions, gaps, and canonical public signing identity produce the same identifiers, proposed entries, signed-payload digest, and approval digest.

The public signing identity is exact-keyed and its Ed25519 raw key, fingerprint, and canonical DER SubjectPublicKeyInfo encoding must all describe the same key; the redundant SPKI encoding is validated rather than separately repeated in the inspection.

The inspection intentionally discloses the operator-authored plan, exact Git-state metadata and repository-relative paths, artifact descriptors, allowlisted Entire identifiers and timestamps, gap codes, exclusions, and the public signer identity.

The inspection never contains the caller's raw Entire JSON, provider-authored prose or errors, transcript, prompts, responses, model metadata, reported files, token counts, Git patch or untracked-file bytes, or private signing material; changing excluded provider prose therefore deliberately leaves the approval digest unchanged, while changing any allowlisted provider projection changes it.

## Residual limits

Entire 0.9 checkpoint-detail discovery may fetch provider data, so this package deliberately accepts only caller-supplied JSON and cannot prove how the caller obtained it.

The archive contains a minimal structural projection rather than provider history, and provider timestamps or session identifiers remain untrusted provider assertions even though their bytes are signed by the local device.

There is no prior-checkpoint lineage, independent evidence, completion claim, multi-device trust policy, revocation, archive filesystem writer, or CLI integration in this slice.

Store persistence is a sequence of individually atomic idempotent writes rather than a multi-object transaction, and an interrupted run can leave unreferenced approved blobs before a retry finishes the event chain.

An in-memory store-write plan is a post-approval capability, not a portable proof of human consent: validation proves that its bytes form one internally consistent signed archive and exact event chain, but its `approvalDigest` cannot independently authenticate who reviewed the inspection, so callers must not accept store plans deserialized from an untrusted source.

The signing capability is injected and may perform implementation-specific work while signing; this package copies every returned archive byte before verification so a signer cannot later mutate retained buffers, but callers can still mutate their own returned `Uint8Array` values and should reverify an archive after such mutation or transport.

The archive and store validators accept the UTC-boundary leap-second form, while the current `captureGitState` producer accepts only ordinary seconds; callers using that producer must choose an ordinary-second `capturedAt` until the producer policy is unified.

The exact store plan may contain Git artifacts larger than the local store's default per-blob limit, so a caller must make an explicit bounded store-limit decision rather than silently truncating or omitting approved bytes.

Run this slice with `pnpm exec prettier --check "packages/handoff/**/*.{ts,md}"`, `pnpm exec tsc --noEmit`, and `pnpm exec tsx --test "packages/handoff/**/*.test.ts"`.
