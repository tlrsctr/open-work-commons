# Open Work Commons

Open Work Commons (OWC) is open, local-first infrastructure for moving human-and-agent work between tools without surrendering durable context to one agent, editor, tracker, or host.

The first proof is intentionally narrow: turn an operator-approved work checkpoint and exact local Git state into a signed, provider-neutral archive; verify it without a network account; then compile a bounded, cited resume bundle for another coding agent. This is a portability and trust primitive, not a hosted product or an agent orchestrator.

The longer-term direction is public infrastructure for work, learning, research, and civic collaboration that people can inspect, export, replace, and continue operating if every contributing company disappears. The [vision and constitutional principles](VISION.md) define that direction.

## Why this exists

Agent work today is usually trapped inside a provider session, while source control captures code but not the objective, human decisions, open questions, exclusions, or honest uncertainty needed to continue the work safely.

OWC makes continuity a user-owned artifact. A checkpoint can bind operator-authored intent to exact Git bytes, keep provider claims separate from evidence, disclose what was excluded, and remain verifiable after the original provider is unavailable.

## Current developer preview

The repository contains an executable, source-only vertical slice for a two-phase Entire 0.9 handoff:

1. `owc handoff inspect` reads a strict operator plan, caller-supplied Entire checkpoint-detail JSON, exact local Git state, and the public device identity; it returns a complete sanitized proposal and one approval digest without signing or writing.
2. `owc handoff create` recaptures the inputs, requires that exact approval digest, signs with the existing local device identity, verifies the result, persists only the approved bytes, and publishes a new unpacked archive directory without overwrite.
3. `owc archive verify` checks schemas, digests, signature, graph integrity, signer policy, and optionally the current local Git repository without contacting a provider.
4. `owc resume compile` emits a deterministic, budget-bounded Markdown or JSON handoff for Codex or Claude from a verified archive.

This is pre-alpha developer-preview software: there is no published package or supported migration promise, and the two-direction human/agent benchmark runs required for a v0 release have not been collected. Passing unit and conformance suites is implementation evidence, not proof that the broader product promise is complete.

See the [15-minute local quickstart](docs/release/quickstart.md), [support matrix](docs/release/support-matrix.md), and [release checklist](docs/release/release-checklist.md).

## Trust boundary

- The operator writes the objective, decisions, questions, constraints, next action, sensitivity, and retention policy.
- Entire is untrusted, replaceable input. The v0 adapter retains only a small structural projection and explicit import gaps.
- Raw transcripts, prompts, responses, provider summaries, hidden reasoning, reported file lists, and unknown provider fields are excluded by default.
- Git state is captured locally without fetching, hooks, configured filters, or provider-reported file claims.
- An Ed25519 signature proves which device key asserted exact bytes and that those bytes did not change; it does not prove the assertions are true.
- Signer trust is an explicit local policy. A valid self-contained signature is not automatically a trusted identity.
- Archive verification and resume compilation require no provider account, hosted API, model call, or network request.

## Architecture

```text
strict operator plan       caller-supplied Entire 0.9 JSON
         |                              |
         +------------+-----------------+
                      |
               sanitized proposal <--------- exact local Git state
                      |
              exact human approval
                      |
                signed OWC archive
                 /              \
                v                v
       offline verification   bounded resume bundle
                |                |
                v                v
         local trust policy   Codex or Claude
```

Entire is an adapter, not the canonical data model. The schemas, conformance fixtures, signing and verification behavior, and export format belong to the commons and must remain independently implementable.

## Try the repository

Requirements for the tested path are Git, pnpm 11.16, and Node.js 22 or 24 on Ubuntu 24.04 or macOS 14. Entire is optional for the committed synthetic handoff because its checkpoint-detail JSON is already supplied.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm check
pnpm build
pnpm owc init
pnpm owc handoff inspect --plan=examples/handoff-v0/operator-plan.json --entire-detail=examples/handoff-v0/entire-checkpoint-detail.sanitized.json --captured-at=2026-08-07T12:00:00Z --json
```

Inspection is read-only. Continue with the exact approval, archive verification, local Git comparison, and resume compilation in the [quickstart](docs/release/quickstart.md).

The independent archive fixture and frozen handoff benchmark can also be checked directly:

```sh
pnpm owc archive verify conformance/valid/minimal --allow-untrusted-signer --json
pnpm benchmark:verify
pnpm benchmark:public
pnpm benchmark:reference
```

The interrupted benchmark implementation intentionally fails some held-out acceptance cases; the separately integrity-locked reference demonstrates that all cases are solvable. This is benchmark-harness evidence, not yet a measured Codex-to-Claude or Claude-to-Codex result.

## Repository layout

```text
apps/cli/                  command-line reference client
packages/core/             shared runtime and readiness contracts
packages/handoff/          exact two-phase inspect, approve, and create flow
packages/archive/          deterministic signing and offline verification
packages/store/            fail-closed local events and content-addressed blobs
packages/identity/         owner-only Ed25519 device-signing capability
packages/git-state/        exact, remote-free Git-state capture and comparison
packages/resume/           bounded, cited Codex and Claude handoffs
packages/adapters/entire/  replaceable Entire capability and import adapter
schemas/v0/                normative JSON Schemas
conformance/               independent valid, invalid, and malicious fixtures
benchmarks/handoff-v0/     frozen cross-agent handoff benchmark
examples/handoff-v0/       fictional inspect-and-create inputs
docs/rfcs/                 protocol decisions and compatibility rules
docs/security/             trust, privacy, retention, and threat model
docs/release/              quickstart, support boundary, and release gates
```

## Deliberate v0 limits

- No multiplayer CRDT collaboration, DeltaDB replacement, team synchronization, federation, or hosted account.
- No project manager, context-graph explorer, general agent runtime, or automatic issue-state mutation.
- No transcript archive, hidden chain-of-thought access, or permanent capture of every prompt, token, keystroke, or tool output.
- No `.owc.tar.zst` container, OS credential-store adapter, device revocation, or multi-device trust policy yet.
- No Windows support claim, binary package, registry release, hosted service, or stable schema migration promise yet.
- Entire checkpoint discovery can use provider behavior outside OWC; the approved handoff command accepts already-supplied JSON so review and creation do not invoke a checkpoint fetch.

Start with the [v0 product requirements](docs/product/PRD-v0-portable-agent-work-handoff.md), then read the normative [boundary and trust model](docs/rfcs/RFC-000-v0-boundary-and-trust.md), [event vocabulary](docs/rfcs/RFC-001-event-session-checkpoint-vocabulary.md), [archive profile](docs/rfcs/RFC-002-portable-archive.md), and [security threat model](docs/security/threat-model-v0.md).

The first implementation backlog is a portable [Git-owned Plane manifest](plane/v0-backlog.json). Its [bootstrap instructions](plane/README.md) keep the public specification separate from private Plane host, workspace, and credential configuration.

## License

The current client, SDK, schemas, conformance tests, and migration tooling are Apache-2.0. A future shared server or official hosted-capable application may use AGPL-3.0-or-later in a separately licensed package.
