# Independent readiness audit

- Audit date: 2026-08-09
- Scope: the source-only Open Work Commons v0 portable-handoff vertical slice
- Auditor posture: adversarial release engineering, independent of the implementation work packets
- Verdict: **developer preview; ready for the first signed-off local commit, not alpha and not release-ready**

## Executive verdict

No stop-ship defect was found in the narrow local workflow that inspects an operator-approved proposal, binds exact Git state, creates a signed archive, verifies it without a provider account, and compiles bounded Codex and Claude resume bundles.

The implementation is strong enough to preserve as the first signed-off source baseline. It is not alpha because the declared operating-system and Node.js CI matrix has not run on a canonical remote, the four frozen cross-agent benchmark conditions have not been collected, a second isolated-machine verification has not been demonstrated, and the security boundary has not received independent review. It is not a release because there is no public distribution, versioned CLI, changelog, SBOM, tag, signed artifact, upgrade promise, or supported security-reporting channel.

The security policy remains controlling: this preview must not be used for secrets, regulated data, production incidents, or other sensitive work.

## Audit method

The uncommitted source tree was copied to a fresh temporary directory while excluding `.git`, `node_modules`, `dist`, and `.owc`. The copy was initialized as a new Git repository and committed with a synthetic audit identity so exact Git capture could be exercised. Dependencies were installed from the committed lockfile. Generated state and archives were written only inside the disposable audit environment.

The audit host ran macOS on arm64 with Node.js 26.5.1, pnpm 11.16.0, Git 2.50.1, and actionlint 1.7.12. Node.js 26 is outside the documented Node 22/24 test matrix, so this local result does not substitute for the configured CI matrix.

Representative commands, with disposable paths and public digests replaced by placeholders, were:

```sh
pnpm install --frozen-lockfile
pnpm format:check
pnpm typecheck
pnpm test
pnpm benchmark:verify
pnpm benchmark:public
pnpm benchmark:reference
pnpm plane:validate
pnpm check
pnpm build
actionlint .github/workflows/ci.yml
pnpm audit --prod --audit-level high

$CLI --help
$CLI --version
$CLI init --json
$CLI handoff inspect --plan=examples/handoff-v0/operator-plan.json --entire-detail=examples/handoff-v0/entire-checkpoint-detail.sanitized.json --captured-at=2026-08-07T12:00:00Z --json
$CLI handoff create --plan=examples/handoff-v0/operator-plan.json --entire-detail=examples/handoff-v0/entire-checkpoint-detail.sanitized.json --captured-at=2026-08-07T12:00:00Z --approve=$APPROVAL --output=$NEW_ARCHIVE --json
$CLI archive verify $NEW_ARCHIVE --trust=$FINGERPRINT --repo=. --json
$CLI resume compile $NEW_ARCHIVE --target=codex --max-items=64 --max-bytes=32768 --trust=$FINGERPRINT --json
$CLI resume compile $NEW_ARCHIVE --target=claude --max-items=64 --max-bytes=32768 --trust=$FINGERPRINT --json
```

## Gate evidence

| Gate                        | Result             | Evidence                                                                                                                                                                               |
| --------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frozen install              | Pass               | The lockfile was accepted by pnpm's supply-chain policy check; 14 development packages were installed from 39 lockfile entries.                                                        |
| Formatting                  | Pass               | All matched files passed Prettier.                                                                                                                                                     |
| TypeScript                  | Pass               | `tsc --noEmit` and the emitting build both exited successfully.                                                                                                                        |
| Composite repository check  | Pass               | `pnpm check` exited zero.                                                                                                                                                              |
| Unit and conformance tests  | Pass               | 260 tests passed, with no failure, skip, cancellation, or todo.                                                                                                                        |
| Malicious corpus            | Pass               | 55 deterministic uniquely named vectors ran: 52 required failures and 3 controlled successes.                                                                                          |
| Benchmark custody           | Pass               | Seven frozen files matched their locked SHA-256 values.                                                                                                                                |
| Benchmark behavior          | Pass as instrument | Public interruption tests passed 2/2; the integrity-locked reference passed 10/10; the deliberately interrupted implementation passed 3/10 hidden cases and failed 7/10 as documented. |
| Plane manifest              | Pass locally       | Manifest-only validation reported 13 work items and 21 blocker relations.                                                                                                              |
| Workflow lint               | Pass               | actionlint reported no issue; every GitHub Action reference is pinned to a full commit SHA.                                                                                            |
| Production dependency audit | Pass               | pnpm reported no known vulnerability and the root package has no production dependency.                                                                                                |
| Compiled help               | Pass               | `--help` exited zero and listed the complete source-preview command surface.                                                                                                           |
| Compiled version            | Gap                | `--version` exited 2 with a fixed unknown-option diagnostic.                                                                                                                           |

## End-to-end handoff evidence

Inspection was byte-identical across two runs with the same normative inputs. Hashing every existing `.owc` file before and after inspection showed no change, and the command reported `signed=false`, `persisted=false`, `archive_published=false`, and `provider_checkpoint_command_invoked=false`. The proposal contained six signed entries and exposed the exact approval digest without raw provider prose, Git artifact bytes, provider error text, or private key material.

Creation succeeded only with the exact inspected approval. It recaptured the proposal, reported `approval_recomputed=true`, verified the archive in memory, persisted the exact policy-authorized bytes, and published a new archive. Repeating the same approved operation to a second fresh output path produced a byte-identical archive and an idempotent store replay.

Reusing an existing output path exited 4 with `handoff_output_exists` and did not overwrite the archive. After introducing Git drift, reusing the old approval exited 4 with `handoff_approval_mismatch`, created no output, and left every store file byte-identical.

Trusted archive verification exited zero and reported internal integrity valid, signer trust `trusted`, and external repository status `matched`. After Git drift, verification exited nonzero while still reporting internal integrity valid and signer trusted, with the external repository separately reported as `mismatched`.

The generated Codex bundle measured 7,922 JSON bytes and 6,301 Markdown bytes. The generated Claude bundle measured 7,923 JSON bytes and 6,302 Markdown bytes. Both complete serializations were below the declared 32,768-byte budget and reported offline archive re-verification.

Every generated store and archive directory had mode `0700`; every generated file had mode `0600`. Runtime scans found no excluded provider canary, actual user identifier, private project identifier, host path, token pattern, or bearer credential in inspection, archive, verification, or resume output.

An adjacent unlisted hostile file did not enter the logical archive, as specified. Modifying a listed checkpoint member caused verification to exit 7 with internal integrity invalid; the hostile bytes were absent from diagnostics. The manifest signature remained independently reported as valid and trusted, which correctly distinguishes a trusted signed manifest from entry bytes that no longer satisfy it.

## Offline and implementation-independence evidence

The compiled verifier succeeded with an empty environment, a fresh empty home directory, and a restricted `PATH` containing no Entire executable. The root has no production dependencies. A production-source scan found no imports of Node network modules and no production `fetch`, XMLHttpRequest, or WebSocket call in the archive, handoff, Git-state, resume, identity, store, or CLI implementation.

The enclosing host refused application of an additional `sandbox-exec` network-denial profile, so this audit does not claim an operating-system-level packet-denial observation. The provider-free execution, dependency graph, subprocess allowlist tests, and source scan support the offline design, but an alpha candidate should repeat verification inside a network namespace or equivalent isolated machine.

The conformance harness reimplements canonical JSON, safe JSON parsing, path checks, cryptographic verification, graph traversal, and semantic reference checks without importing `packages/archive` or `packages/resume`. The malicious oracle imports only the separate harness, local corpus code, JSON Schemas, Ajv, and Node standard-library primitives. Source comparisons confirmed that the harness files are separate implementations rather than imports or generated aliases. This is meaningful implementation independence inside one TypeScript repository, not proof from a second language or organization.

## Privacy, provenance, and license review

The tracked-source scan found no actual username, host path, private Plane host, unrelated private-product identifier, known token prefix, bearer credential, or PEM private key. Seven `/Users/example/...` values are deliberate synthetic redaction canaries in CLI tests. The malicious corpus has a deterministic disposable signing seed, and the published minimal archive explicitly labels its embedded identity as test-only. No raw transcript or real provider output was found.

The repository is Apache-2.0 and uses Developer Certificate of Origin sign-off. Its direct development dependencies report MIT, BSD-3-Clause, or Apache-2.0 licenses, and it has no production package dependency. Entire is invoked as a replaceable external CLI or consumed through caller-supplied sanitized JSON; no Entire source is vendored. The official [Entire CLI repository](https://github.com/entireio/cli) and [v0.9.0 Go module record](https://pkg.go.dev/github.com/entireio/cli@v0.9.0) identify the upstream code as MIT-licensed, so the current adapter boundary is compatible with the stated Apache-2.0 source distribution.

No automated gitleaks or TruffleHog binary was available on the audit host, so the secret result is a tracked-source pattern scan plus fixture and runtime canary tests rather than a second commercial-grade detector. Distribution should add a dedicated secret scanner, SBOM, checksums, and third-party attribution inventory.

## Findings by severity

### Blocker

No code-level blocker was found for preserving and sharing the project as an explicitly unsupported source-only developer preview.

Publishing an alpha or supported release is blocked by the missing evidence and distribution controls listed below.

### High

1. The supported matrix is configured but unproven. The audit-start tree had no source commit, canonical remote, or CI run, so Ubuntu 24.04 and macOS 14 on Node 22 and 24 remain targets rather than observed release evidence.
2. Product-level transfer evidence is missing. The four frozen Codex/Claude baseline and assisted benchmark runs have not been conducted, and no second-machine copy-and-verify result exists.
3. The signature, path, subprocess, identity-file, and interrupted-persistence boundaries have extensive tests but no independent security review. That review is required before alpha use with meaningful work data.

### Medium

1. The compiled CLI has no `--version`; the root package is private at `0.0.0` and has no repository, homepage, bug tracker, changelog, or packaged artifact metadata.
2. `engines.node` declares `>=22`, which is broader than the documented and configured Node 22/24 matrix. Either constrain the declaration or expand continuous testing before making a support claim.
3. Operating-system-level network denial was not observable on this host. Repeat the verifier and resume compiler in a network namespace or an isolated second machine for alpha evidence.
4. Live `pnpm plane:check` was not authorized in the clean environment and correctly failed for missing Plane configuration. The Git-owned 13-item/21-relation manifest is valid, but live reconciliation remains an operational handoff.
5. Private vulnerability reporting and a monitored security contact are not configured. The current source-host-owner fallback is suitable only for pre-release work.

### Low

1. No dedicated secret-scanning binary ran; current evidence combines targeted patterns, synthetic canaries, runtime output scans, and repository review.
2. `CHANGELOG.md`, `NOTICE`, `CODE_OF_CONDUCT.md`, and `CODEOWNERS` are absent. A `NOTICE` file is not required by the current no-vendored-code boundary, but the distribution process should make that decision explicit.
3. The independent oracle remains in the same language, repository, and dependency ecosystem as the reference implementation. A second implementation would materially strengthen a future interoperability claim.

## Minimum path to alpha

1. Create the first DCO-signed source commit, establish the canonical public remote, and make the configured four-pair CI matrix pass from a clean checkout.
2. Add a real CLI version, align Node engine metadata with tested support, publish repository and issue metadata, enable private vulnerability reporting, and produce a changelog and SBOM.
3. Run all four frozen cross-agent benchmark conditions without evaluator leakage and preserve the raw measures defined by the benchmark.
4. Copy an archive to a second isolated environment, deny network access, verify against an explicit trust anchor, compare the local repository, and compile both resume targets.
5. Obtain an independent security review focused on signature semantics, logical versus filesystem paths, symlink and hard-link handling, local key permissions, subprocess boundaries, approval drift, resource limits, and interrupted persistence.
6. Reconcile the Git-owned Plane manifest after credential rotation. Plane is an operational projection and must not become a protocol or verification dependency.

After those steps pass, the project can reasonably call itself an alpha. A supported release still requires a chosen distribution format, reproducible artifacts, checksums, release signing, compatibility and migration policy, protected branch, tag, and final release audit.
