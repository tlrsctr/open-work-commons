# Developer-preview quickstart

This walkthrough exercises the complete source-only v0 handoff path in less than 15 minutes after obtaining a fresh checkout. It uses only fictional example input and writes the generated archive outside the repository.

## 1. Prepare the checkout

Use Node.js 22 or 24, pnpm 11.16, Git, and either Ubuntu 24.04 or macOS 14. The source checkout must have at least one commit because exact Git capture binds the archive to `HEAD`.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm check
```

The install step may use the package registry. The later archive verification and resume compilation commands do not need a provider account, hosted API, or network request.

## 2. Create the private workspace store and device identity

```sh
pnpm owc init
pnpm owc identity status --json
```

`owc init` creates `.owc/` with owner-only permissions and an Ed25519 device identity. `.owc/` is Git-ignored. Record `data.identity.fingerprint` from the JSON status as the local trust anchor; do not copy or expose files from `.owc/`.

## 3. Inspect the exact proposal

```sh
pnpm owc handoff inspect --plan=examples/handoff-v0/operator-plan.json --entire-detail=examples/handoff-v0/entire-checkpoint-detail.sanitized.json --captured-at=2026-08-07T12:00:00Z --json
```

Inspection must not sign, persist, publish an archive, or call Entire. Review the normalized operator plan, minimal provider projection, Git-state digest, every archive entry, exclusions, gaps, signer identity, limits, and proposed payload digest. Confirm that no `SYNTHETIC_EXCLUDED_*` canary from the provider input appears in the output.

Record `data.review.approvalDigest` exactly, including the `sha256:` prefix. Approval covers the complete proposal; a Git change, input change, timestamp change, or signer change makes it invalid.

```sh
APPROVAL_DIGEST='sha256:paste-the-inspection-approval-digest-here'
```

## 4. Create one approved archive

Choose a fresh output parent outside the repository. The command refuses an existing output directory instead of merging with or overwriting it.

```sh
OWC_DEMO_ROOT="$(mktemp -d)"
pnpm owc handoff create --plan=examples/handoff-v0/operator-plan.json --entire-detail=examples/handoff-v0/entire-checkpoint-detail.sanitized.json --captured-at=2026-08-07T12:00:00Z --approve="$APPROVAL_DIGEST" --output="$OWC_DEMO_ROOT/archive" --json
```

Creation recaptures Git and recomputes the proposal before checking approval. It opens the existing device identity, signs only after an exact match, verifies the archive in memory, idempotently persists only the approved blobs and events, and atomically publishes the owner-only unpacked archive directory.

If creation reports `approval_mismatch`, rerun inspection and review the new proposal. Never reuse an approval digest after changing input or repository state.

## 5. Verify bytes, signer, and local Git state

Copy `data.identity.fingerprint` from step 2 into the following variable.

```sh
SIGNER_FINGERPRINT='sha256:paste-the-device-fingerprint-here'
pnpm owc archive verify "$OWC_DEMO_ROOT/archive" --trust="$SIGNER_FINGERPRINT" --repo=. --json
```

A successful result has valid internal integrity, a valid and trusted signature, and `matched` external repository verification. Internal archive integrity and the optional current-repository comparison are separate results; repository mismatch never rewrites the signed archive.

To demonstrate self-contained byte integrity without asserting identity trust, use `--allow-untrusted-signer` instead of `--trust=...`. That flag is an explicit integrity-only acknowledgement, not a trust shortcut.

## 6. Compile a bounded resume bundle

```sh
pnpm owc resume compile "$OWC_DEMO_ROOT/archive" --target=claude --max-items=64 --max-bytes=32768 --trust="$SIGNER_FINGERPRINT"
```

The default output is deterministic Markdown intended for the target agent. Add `--json` to receive the schema-valid bundle plus separate JSON and Markdown byte lengths and digests. Both serializations must fit the declared byte budget.

## 7. Inspect the generated boundary

The archive is an unpacked directory whose manifest lists every permitted entry by path, role, digest, byte length, and verification requirement. Search it for the synthetic exclusion marker; the command should print no matches.

```sh
grep -R "SYNTHETIC_EXCLUDED_" "$OWC_DEMO_ROOT/archive"
```

The generated archive and demo directory can be removed when finished. The workspace `.owc/` store remains local and private; remove it only if you intentionally want to destroy the local identity and persisted checkpoint data.

## Real Entire input

For real work, independently obtain an Entire 0.9 checkpoint-detail JSON object, review and redact it before placing it on disk, and bind its exact checkpoint identifier in a strict operator plan. OWC's handoff commands do not invoke Entire checkpoint discovery or fetch the detail on your behalf.

Provider timestamps and session identifiers remain untrusted provider assertions even after the local device signs the structural projection. Do not present them as independent evidence, test results, authorship proof, or completion proof.
