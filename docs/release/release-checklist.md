# Release checklist

Open Work Commons is currently a pre-alpha, source-only developer preview. A green local suite is necessary but is not, by itself, permission to describe the broader v0 promise as released.

## Developer-preview readiness gate

- [ ] `pnpm install --frozen-lockfile` succeeds from a clean source checkout on every supported CI pair.
- [ ] `pnpm check` passes formatting, typechecking, unit/conformance tests, frozen benchmark integrity, public/reference benchmark behavior, and Plane-manifest validation.
- [ ] `pnpm build` succeeds and the compiled CLI help command runs.
- [ ] The synthetic handoff smoke initializes a fresh identity, inspects without mutation, creates only after exact approval, publishes a new archive, and excludes every synthetic provider-content canary.
- [ ] The generated archive verifies against its device fingerprint without a provider and matches an independent recapture of the local Git repository.
- [ ] The generated archive compiles into bounded Codex and Claude resume serializations.
- [ ] The malicious corpus passes through the independent conformance oracle with stable diagnostic categories.
- [ ] `pnpm audit --prod --audit-level high` reports no high-or-critical production dependency finding.
- [ ] Workflow YAML passes `actionlint` and every action is pinned to a full commit SHA.
- [ ] A clean-checkout audit records exact commands, versions, outcomes, and remaining blockers without leaking a username, machine path, token, transcript, or private repository data.

## v0 alpha product-evidence gate

- [ ] Run and preserve an unassisted baseline and OWC-assisted Codex-to-Claude handoff against the frozen benchmark.
- [ ] Run and preserve an unassisted baseline and OWC-assisted Claude-to-Codex handoff against the same frozen benchmark.
- [ ] Record task success, unsupported claims, evidence quality, resume size, elapsed time, and operator interventions without retaining raw private transcripts.
- [ ] Demonstrate archive copy, trusted offline verification, and successful resume on a second clean machine or isolated environment.
- [ ] Test signer mismatch, stale approval, Git drift, archive tampering, symlink input, duplicate-key JSON, resource exhaustion, interrupted store persistence, and output-path collision in release-candidate builds.
- [ ] Review the threat model, schemas, RFCs, CLI help, examples, and limitations for one consistent compatibility and trust story.
- [ ] Obtain an independent security review of the signature boundary, path handling, local identity storage, subprocess restrictions, and malicious corpus.

## Distribution gate

- [ ] Create a canonical public repository URL and protect the default branch.
- [ ] Select the first public version and remove the private `0.0.0` package placeholder only after packaging scope is decided.
- [ ] Publish source provenance, Apache-2.0 notices, DCO contribution rules, support boundary, changelog, and upgrade or archive-compatibility statement.
- [ ] Decide which artifacts are distributed; do not imply support for npm, Homebrew, containers, standalone binaries, or `.owc.tar.zst` until each artifact is reproducibly built and verified.
- [ ] Generate a software bill of materials and archive checksums for every distributed artifact.
- [ ] Tag and sign the release, verify it from a clean checkout, and attach the final readiness audit.

## Explicit non-blockers for the narrow preview

- A hosted service, team synchronization, web UI, context graph, and general agent runtime are not required for the portable-handoff developer preview.
- Entire may remain the first adapter because the archive, schemas, verifier, and resume bundle are provider-neutral; a second capture adapter remains product evidence for later portability claims.
- Windows support is not required if all docs and release metadata continue to say unsupported.

## Stop-ship conditions

Do not publish even a developer preview if any supported CI pair is red; exact approval can be bypassed; signing or persistence occurs during inspection; a provider-content canary reaches inspection or archive output; verification requires a network/provider account; an archive can escape its output root or follow a symlink; signer trust is conflated with signature validity; Git mismatch is hidden; deterministic inputs produce unstable proposal bytes; or the repository contains a credential, private path, raw transcript, or unpublished user data.

## Current known release blockers

- No canonical public remote, tag, changelog, or packaged artifact is configured.
- Cross-agent Codex-to-Claude and Claude-to-Codex benchmark evidence has not been collected.
- The root package remains private at `0.0.0`, so the supported path is a source checkout.
- Container encoding, OS-backed credential storage, revocation, recovery, and multi-device trust are deliberately unimplemented.
- Windows is unsupported and untested.

These blockers do not invalidate the narrow local proof, but they prevent a claim that OWC v0 is a supported, generally available release.
