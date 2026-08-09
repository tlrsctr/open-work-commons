# Product requirements: portable agent-work handoff v0

- Status: Candidate
- Product: Open Work Commons
- Plane project: OWC
- Last updated: 2026-08-07

## Product thesis

People should be able to leave an agent, editor, employer, or hosted service without abandoning the state of their work.

Open Work Commons starts with one narrow, falsifiable proof: a person can interrupt a coding task in Codex or Claude, export a signed and inspectable checkpoint, verify it without a network connection, and continue with the other agent without copying the original transcript.

This is an exit-right primitive rather than another agent interface. The durable value is the provider-neutral checkpoint and its conformance contract. Entire is the pragmatic first capture provider, not an authority over the format or a permanent dependency.

## Problem

Agent work is usually trapped in transient chat history, product-specific session stores, editor state, and a human's memory. Git preserves resulting files but usually omits the objective, constraints, decisions, evidence, unknowns, and intended next action that make work continuable.

Copying a full transcript is a poor interoperability contract: it is private, verbose, provider-specific, difficult to verify, vulnerable to prompt injection, and often contains irrelevant or sensitive material.

## Primary user

The v0 user is an individual software contributor who works in a local Git repository with Codex and Claude and wants to move an interrupted task between them without a hosted coordination service.

The first secondary users are maintainers building another capture adapter or verifier, and teams evaluating whether a handoff artifact is trustworthy enough to accept.

## Job to be done

When I need to stop, switch agents, or move machines, help me preserve the smallest sufficient and verifiable state of my work so I can continue safely without exposing my complete conversation history or depending on one vendor.

## v0 promise

On a clean supported machine, a user can:

1. inspect whether Git and Entire are locally ready;
2. select a locally captured Codex or Claude checkpoint;
3. review what Open Work Commons will include and exclude;
4. bind the checkpoint to exact Git state;
5. create a signed portable archive;
6. copy it by any ordinary file-transfer mechanism;
7. verify schemas, digests, signature, signer trust, references, and Git binding fully offline;
8. compile a size-bounded, cited resume bundle; and
9. continue the seeded task in the other agent without supplying the source transcript.

## Product principles

- Local first: core capture, export, verification, and resume compilation require no account or service.
- Exit is a feature: the archive remains intelligible and verifiable when Entire and this reference CLI are absent.
- Evidence is not assertion: an agent claim never silently becomes test evidence.
- Integrity is not trust: signature validity and accepted signer identity are separate states.
- Minimum sufficient capture: raw transcripts are not imported or archived by default; upstream provider retention is disclosed separately.
- Unknown stays unknown: adapters do not invent identity, order, authority, results, or completion.
- Safe by construction: archive content is untrusted data and is never executed by verification or compilation.
- Replaceable edges, stable center: providers and user interfaces can change while schemas and conformance behavior remain portable.

## Scope

### Included

- Node.js reference CLI for macOS ARM64 and Linux x86_64.
- Entire CLI 0.9 or later as the first local capture adapter.
- Codex-to-Claude and Claude-to-Codex handoffs.
- Provider capability inspection and explicit unavailable-field reporting.
- One local Ed25519 device signer.
- Provider-neutral session events and immutable checkpoints.
- Exact Git commit, tree, dirty patch, and declared untracked-file binding.
- Signed logical archive with deterministic payload digest.
- Offline, fail-closed verification with bounded resource use.
- JSON and Markdown resume bundles with path-and-digest citations.
- Public schemas, valid fixtures, malicious mutation cases, and a seeded benchmark.

### Excluded

- Raw-transcript import or archive inclusion by default.
- Hidden chain-of-thought capture.
- A DeltaDB replacement, CRDT collaboration, or shared live document.
- Team synchronization, federation, hosted identity, remote revocation, or organizational policy management.
- Agent orchestration, automatic tool execution, or automatic Plane state changes.
- A web application, graph explorer, marketplace, or hosted service.
- Reimplementing Entire while its MIT-licensed local CLI satisfies the v0 boundary.

## Core product loop

```text
inspect readiness
      ↓
select + normalize local checkpoint
      ↓
review inclusions, exclusions, and unknowns
      ↓
bind exact Git state + sign archive
      ↓
transfer ordinary file
      ↓
verify integrity and signer trust offline
      ↓
compile bounded cited resume bundle
      ↓
continue in another agent and capture evidence
```

## Entire adapter policy

The reference implementation may automatically invoke only documented, strictly local, read-only Entire commands. It must not log in, call Entire's hosted API, mutate provider state, or request transcript fields.

Entire 0.9 checkpoint list and detail commands may discover or fetch remote refs. Strict-local mode therefore reports that boundary and accepts explicitly supplied structured JSON for the current importer. A future opt-in command may authorize provider fetch behavior visibly, but archive verification remains fully offline.

Entire's own source-side transcript retention is outside the Open Work Commons archive boundary and must be disclosed to the user. Excluding a transcript from an OWC archive does not claim that Entire never created or retained one.

The adapter is replaceable when any of these conditions occur:

- the required local structured data becomes unavailable;
- a hosted account becomes mandatory for the promised flow;
- provider terms or licensing no longer permit distribution or commercial use;
- privacy behavior cannot be made visible and bounded; or
- an independent native recorder is demonstrably simpler or safer.

## Success measures

### North-star measure

Verified cross-agent handoff success rate: the percentage of seeded interrupted tasks that a fresh receiving agent completes against fixed acceptance tests using the repository and resume bundle, without the original transcript.

### Release gates

- Both Codex-to-Claude and Claude-to-Codex assisted runs pass the seeded task.
- Verification completes with network access disabled and no vendor account.
- Every published tamper case fails closed with a stable diagnostic category.
- Equal normative inputs reproduce the published payload digest.
- The configured resume item budget is never exceeded, and neither complete returned resume serialization exceeds the shared UTF-8 byte budget; the measurement includes identity metadata, citations, sources, delimiters, and omission reporting.
- Secret canaries do not reach OWC durable storage, logs, fixtures, or archives.
- A second implementation can validate the golden archive without importing reference-CLI code.
- A new user completes the post-install quickstart within fifteen minutes.

### Comparative measures

- Time or tokens to first correct action.
- Repeated questions already answered in the source checkpoint.
- Constraints missed or contradicted.
- Acceptance-test completion.
- Human review and correction effort.
- Resume-bundle bytes versus source provider-session bytes.

Results may be null or negative. Metrics and acceptance tests must be frozen before assisted runs.

The frozen synthetic v0 fixture, interruption snapshot, source-session decisions, evaluator, measures, and byte digests live in [`benchmarks/handoff-v0`](../../benchmarks/handoff-v0/README.md). Publishing the benchmark does not satisfy this gate by itself; the four baseline and assisted runs still require independent execution and recorded evidence.

## Delivery sequence

1. Trust contract, repository baseline, and seeded benchmark: `OWC-V0-TRUST`, `OWC-V0-REPO`, `OWC-V0-BENCHMARK`.
2. Normative schemas and conformance corpus: `OWC-V0-SCHEMAS`.
3. Local store, Git binding, and Entire import: `OWC-V0-STORE`, `OWC-V0-GIT`, `OWC-V0-ENTIRE`.
4. Signed archive and offline verifier: `OWC-V0-ARCHIVE`, `OWC-V0-VERIFY`.
5. Bounded resume compiler and two-direction proof: `OWC-V0-RESUME`, `OWC-V0-PROOF`.
6. Clean-machine packaging and public release: `OWC-V0-RELEASE`.

The canonical issue specifications and dependencies live in `plane/v0-backlog.json`; Plane owns execution status, assignees, dates, discussion, and evidence.

## Required product states

The CLI must distinguish at least:

- dependency absent;
- installed but unsupported;
- provider disabled for this repository;
- provider status unknown or malformed;
- capture ready;
- archive structurally invalid;
- archive integrity invalid;
- archive signature valid but signer untrusted;
- archive valid and signer trusted; and
- verified archive whose optional external Git match was not checked.

No “success” state may collapse one of these boundaries.

## Open decisions before Candidate becomes Stable

- Exact safe structured Entire command for checkpoint-detail import in 0.9.
- OS credential-store abstraction and encrypted file fallback.
- Packed-container profile after the logical unpacked archive is proven.
- Default resource limits by supported platform.
- Trust-anchor import and rotation experience.
- Independent verifier implementation and stewardship home.

## Beyond v0

If the handoff proof succeeds, the same primitives can support personal knowledge continuity, auditable human-agent teamwork, portable employment records chosen by workers, cooperative project spaces, and civic workflows. Those products should consume the commons rather than expanding v0 into an unbounded platform before its first promise is proven.
