# `packages/archive`

This package is the first executable OWC v0 archive trust boundary.

It constructs a deterministic unpacked logical archive, signs the RFC 8785 manifest projection with an Ed25519 device key, and verifies the manifest, entries, core JSON objects, references, and checkpoint graph without network access.

Verification returns archive integrity and local signer trust as separate states.

External repository verification remains a separate result and defaults to `not-checked`.

The CLI can independently attach a bounded `matched`, `mismatched`, or `unavailable` local Git observation after internal archive verification and the operator's signer policy permits use of the archive; that observation never changes `integrity.valid`.

The verifier accepts bytes that are already in memory and never extracts, renders, follows, or executes archive content.

Container decoding for `.owc.tar.zst`, operating-system credential storage, revocation, resume compilation, and complete JSON Schema engine parity are deliberately outside this vertical slice.

The explicit validators cover every required field and the security-relevant constraints for the v0 manifest, event, Git-state, checkpoint, and evidence schemas, including optional checkpoint-to-evidence identity binding.

Run the package tests with `pnpm exec tsx --test "packages/archive/**/*.test.ts"`.
