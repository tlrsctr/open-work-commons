# ADR-0001: Use Entire as the bootstrap capture provider

- Status: Accepted for v0
- Date: 2026-08-07

## Context

Open Work Commons needs real Codex and Claude session checkpoints to prove portable handoff value. Building a new recorder before proving the archive and resume contract would delay the test and create another privacy-sensitive integration surface.

[Entire CLI](https://github.com/entireio/cli) 0.9 is locally installed, its official source repository is MIT-licensed, and it exposes machine-readable capability and checkpoint commands. Its broader hosted platform is not required for the v0 product promise. However, inspection of the 0.9 implementation shows that checkpoint list and detail commands may discover or fetch remote checkpoint refs even though they do not mutate checkpoint content.

Entire may independently retain source transcripts. Open Work Commons cannot claim that excluding transcripts from its own store or archive deletes or disables provider-side copies.

## Decision

Use Entire CLI 0.9 or later as the first replaceable capture-provider adapter.

The adapter may automatically use documented, structured, strictly local, read-only commands only. It must not log in, invoke a hosted API, mutate Entire configuration or checkpoints, scrape human-oriented output, or request raw transcript fields.

Strict-local checkpoint discovery must fail with an explicit capability boundary rather than silently invoking a command that may fetch. The first importer accepts explicitly supplied checkpoint JSON and projects only an allowlist of metadata. Any future command that permits provider-side fetches requires a separate visible user authorization and must remain outside offline verification.

Open Work Commons owns the normalized event vocabulary, checkpoint model, archive schemas, signature rules, verifier behavior, resume bundles, and conformance fixtures. No normative identifier or verification rule may depend on Entire.

## Consequences

The project can test a real cross-agent handoff earlier and can compare its curated archive against existing provider records.

Users must install and enable Entire separately for the first live capture flow. The CLI must report absent, incompatible, disabled, unknown, ready, and “structured but not guaranteed local-only” states distinctly.

Provider-side transcript retention must be disclosed in product and security documentation even when Open Work Commons never imports those bytes.

Adapter fixtures must be synthetic and sanitized. Raw provider output cannot escape the adapter into diagnostics or tests.

## Replacement triggers

Reconsider this decision if structured local checkpoint data becomes unavailable, a hosted account becomes mandatory, licensing no longer permits the intended distribution and commercial use, provider retention cannot be made visible, or a native recorder becomes measurably safer or simpler.

Replacement must preserve the same provider-neutral conformance boundary; it must not fork the core format around a new recorder.
