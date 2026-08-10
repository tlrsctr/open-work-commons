# Two-week novelty and collision scan

- Window: 2026-07-27 through 2026-08-10, inclusive
- Scope: public repositories, releases, official vendor announcements, Hacker News discovery, Latent Space, standards, and academic records
- Decision: go, but only as a signed and independently verifiable work-checkpoint trust layer

## Executive conclusion

The broad category was created repeatedly during this window. GitHub repository search returned 62 new repositories for the exact phrase `agent handoff`, nine for portable agent handoff, and five for verifiable agent handoff. Cross-agent resume, transcript conversion, Git-aware handoffs, encrypted context sharing, and checksummed checkpoint files are already crowded categories.

No public project found in the scan combined all of the following properties:

1. Human inspection and approval bound to the canonical proposal digest before signing or persistence.
2. Recaptured repository identity, commit and tree plus staged, unstaged, and optionally included untracked bytes.
3. A signed, provider-neutral and transcript-minimized work archive with signer trust kept separate from byte integrity.
4. A standalone verifier that requires neither the originating vendor nor network access.
5. An independently implemented conformance oracle and adversarial mutation corpus.
6. Deterministic, cited and byte-bounded resume bundles for competing target agents.

That conjunction remains useful, but it is a trust profile and interoperability substrate rather than a generic handoff product. This scan is product research, not a patent novelty opinion; private, unpublished and unindexed work cannot be ruled out.

## Closest public collisions in the window

| Date       | Project                                                                                           | Direct overlap                                                                                                                                                                     | Remaining OWC distinction                                                                                                                                                                                                             |
| ---------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-07-27 | [Entire CLI v0.9.0](https://github.com/entireio/cli/releases/tag/v0.9.0)                          | Git-ref checkpoints, machine-readable listing, second-device discovery, imported sessions and hidden resume                                                                        | Entire remains a capture adapter: it preserves provider session data, may enumerate remote refs, and does not produce the mandatory operator-approved neutral archive and independent offline trust decision                          |
| 2026-07-29 | [Project Checkpoint v0.3.1](https://github.com/ted0103/ai-project-checkpoint/releases/tag/v0.3.1) | The closest work-artifact collision: explicit scope approval, transcript-free handoff, branch/commit/dirty-file fingerprints and a verified source ZIP                             | Its own safety boundary says the digest is not an adversarial signature and does not authenticate the creator; there is no pinned signer policy, independent conformance verifier or stable provider-neutral event/checkpoint archive |
| 2026-07-30 | [Agent Handoff Kit](https://github.com/whaojie797-design/agent-handoff-kit)                       | Portable task, evidence, decision and handoff files across Codex, Claude, Cursor and Gemini                                                                                        | Markdown state plus a validator, without exact byte capture, signatures or an independent offline verifier                                                                                                                            |
| 2026-08-01 | [Claude-Codex Bridge](https://github.com/nerln/claude-codex-bridge)                               | Bidirectional native-session conversion, deterministic capsule, Git/filesystem snapshot and drift checks                                                                           | Checksums are explicitly not signatures; target formats remain empirical vendor state and there is no independently portable trust artifact                                                                                           |
| 2026-08-02 | [Agent Trust Kit](https://github.com/mauricemohr88-debug/agent-trust-kit)                         | The closest security-boundary collision: allowlisted offline packets, registered clean Git inputs, operator review, output manifests, signed receipts and controller-side rechecks | It secures outbound delegation and returned worker evidence; packet signing is not the mandatory continuation identity, and it does not create a general dirty-worktree checkpoint or cross-agent bounded resume artifact             |
| 2026-08-04 | [Agent Handoff MCP](https://github.com/SarutobiSasuke8/agent-handoff-mcp)                         | Structured handoff lifecycle, authorization and disclosure boundaries                                                                                                              | Coordination transport rather than a self-contained work archive                                                                                                                                                                      |
| 2026-08-06 | [`resume-from` v0.1.7](https://github.com/alexei-led/resume-from/releases/tag/v0.1.7)             | Preview-first Pi, Claude Code and Codex session conversion, filtering, budgeting and native target resume                                                                          | Transfers normalized conversation turns rather than approved minimum-sufficient work; no exact dirty-tree binding, signed portable artifact, signer policy or independent verifier                                                    |
| 2026-08-07 | [OpenAI Codex v0.147.0](https://github.com/openai/codex/releases/tag/rust-v0.147.0)               | Imports Cursor-managed skills and synchronizes imported Claude and Cursor conversations                                                                                            | One-way vendor ingestion, not a user-exportable signed checkpoint with exact Git binding and arbitrary target resume                                                                                                                  |
| 2026-08-07 | [`agent-hop`](https://github.com/hetpatel-11/agent-hop)                                           | Searches local sessions and rewrites real conversation and tool activity into another agent's native format                                                                        | Excellent landing UX, but it transports session history rather than independently verified work state                                                                                                                                 |
| 2026-08-08 | [AgentShare](https://github.com/amazing-aaryan/AgentShare)                                        | Reviewed deterministic context bundles, local encryption and Codex/Claude delivery through a blind relay                                                                           | Encryption protects transport confidentiality but does not establish the OWC signer/trust model or exact repository state; the relay is part of the product path                                                                      |
| 2026-08-09 | [ThreadLoom](https://github.com/eapeal8/threadloom)                                               | User-gated checkpoint and verified handoff around compaction, branch/commit/dirty snapshot, no transcript in automatic checkpoints                                                 | Its SHA-256 footer is explicitly not an authorship signature, Git drift is a warning, and the handoff remains a live-repository navigation document rather than a portable independently verified archive                             |

## Important prior art outside the window

### Portable Agent Memory

[Portable Agent Memory](https://github.com/santhoshravindran7/portable-agent-memory), created 2026-05-10 and licensed Apache-2.0, is the strongest constraint on novelty language. It already defines JSON/CBOR cross-provider memory artifacts, BLAKE3 Merkle-DAG integrity, Ed25519 signatures, capability-scoped disclosure, rehydration and Codex/Claude integrations.

OWC must not claim to be the first signed portable agent-memory protocol. Its distinct profile is operator-authored work continuity: exact repository evidence, pre-signing approval, transcript minimization, out-of-band signer trust, independent conformance and cited bounded resume. Portable Agent Memory is an interoperability and adapter opportunity rather than code to recreate.

### HACP

[Human-Approved Coordination Protocol](https://github.com/joefeser/hacp), created 2026-05-09, already specifies human-approved authority packets, handoff packages, adapter reports, match proofs, human decision records, RFC 8785 digest domains and chain-of-custody semantics. Its prose is CC BY 4.0 and its machine-readable artifacts are Apache-2.0.

OWC must not imply that human-approved custody records or canonical approval digests originated here. HACP deliberately does not define an execution runtime, exact Git archive or cross-agent resume compiler; OWC can become an executable transport/archive profile or bridge beneath that authority layer.

### CatchUp

[CatchUp](https://github.com/wilbeibi/catchup), created 2026-06-26 and licensed MIT, already provides local-first transcript handoff across Claude Code, Codex, Cursor, Cline, Kimi, Antigravity, OpenCode and Pi. It makes the demand for cross-agent continuity concrete while also showing why OWC should not compete primarily on the number of transcript adapters.

## Official product movement

The incumbent direction validates portability demand while remaining provider-controlled. Entire v0.9.0 made Git-ref checkpoints discoverable across devices. Codex v0.147.0 added imported Claude/Cursor conversation synchronization. Claude Code added provider-native teleport, messaging and remote-resume improvements. Cline and Copilot CLI improved native rewind, checkpoints and worktree sessions. MCP added task-oriented protocol work.

None of those releases made a reviewed work checkpoint into a mandatory signed artifact that an unrelated offline implementation could verify and resume elsewhere. OWC should integrate with their capture and landing surfaces, not rebuild every native session converter.

## Demand and research signals

The July 31 essay [The session you cannot take with you](https://earendil.com/posts/session-portability/) and its [Hacker News discussion](https://news.ycombinator.com/item?id=49118781) produced the strongest demand signal in the window. The discussion emphasized exit rights, opaque compaction, provider lock-in and the possibility that user-controlled intent and work structure matter more than lossless transcript transfer.

Recent papers point in the same direction. [Filesystem-Based Memory for LLM Agents](https://arxiv.org/abs/2607.26637) supports local inspectable memory while showing that storage organization alone is insufficient. [Memory Provenance Laundering in LLM Agents](https://arxiv.org/abs/2607.29167) shows how untrusted observations can become apparently authoritative memory. [MutMem](https://arxiv.org/abs/2608.02843) demonstrates academic convergence on signed memory transitions and portable verification.

These are arguments for explicit provenance and authority, not evidence that every memory item or agent summary is true.

## Product decision

Go, with the following public thesis:

> OWC is the open, independently verifiable checkpoint profile for human-and-agent work: bind reviewed intent to exact repository bytes, transfer it without the source transcript, verify it offline, and resume anywhere.

OWC must avoid these claims:

- First cross-agent handoff tool.
- First signed portable agent-memory protocol.
- Lossless migration of hidden model state or reasoning.
- Proof that an agent's claims or test reports are true merely because an archive is signed.
- A complete general solution to agent memory, orchestration or context graphs.

## Immediate interoperability agenda

1. Publish the current source-only developer preview and its independent audit without calling it alpha.
2. Add benchmark comparisons or adapters for Project Checkpoint, Entire, `resume-from` and CatchUp rather than copying their landing UX.
3. Define mapping notes for Portable Agent Memory entries and HACP authority/custody records.
4. Keep the archive verifier, trust separation and malicious conformance corpus independently implementable.
5. Demonstrate the frozen Codex-to-Claude and Claude-to-Codex benchmark on a second network-isolated machine.
