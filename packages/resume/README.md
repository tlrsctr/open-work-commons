# `packages/resume`

This package compiles a bounded JSON and Markdown resume bundle from an OWC logical archive and the successful `ArchiveVerificationResult` for those exact bytes.

The compiler re-verifies the archive offline before parsing any captured entry. It rejects an integrity failure, an explicit signer trust-anchor mismatch, and a supplied-result/archive identity mismatch. It reads only the root checkpoint, its exact Git-state entry, and checkpoint-referenced normalized events. It never reads artifact bodies, executes captured content, follows links, invokes providers, or calls a model.

The compiler returns stable two-space JSON and prompt-facing Markdown, each ending in one LF. `maxUtf8Bytes` is a shared cap that each complete serialization must satisfy independently, including all identity metadata, policy text, headings, citations, sources, delimiters, and omission reporting. `actual_utf8_bytes` is the larger of the complete JSON and Markdown UTF-8 byte lengths. Because both serializations contain that measurement, the compiler resolves the byte-count fixed point before accepting the result; it fails closed if the value cannot stabilize. `maxItems` counts the objective, constraints, Git state and each patch/untracked row, selected claims/decisions/evidence/gaps/questions, exclusions, next action, omission rows, and source-table rows. If either complete serialization cannot fit after deterministic optional-item removal, compilation fails instead of truncating the objective, constraints, exact Git state, exclusions, next action, strings, or UTF-8 code points.

Optional content is retained in this priority order: evidence, explicit decisions, evidence gaps, open questions, then claims. Trimming proceeds in the reverse order and, within a class, removes later source-order items first. Mandatory content is never a trimming candidate.

Captured strings are copied exactly rather than summarized and are rendered as JSON string literals inside visible untrusted-content markers. Claims remain separate in the `openworkcommons.org/claims` extension because the v0 resume schema has no claim field. Full Git state, cited exclusion policy, and the deterministic material-omission report are likewise preserved as namespaced extensions. A decision is emitted only for an explicitly referenced `human.intervened` event whose inline normalized payload has a non-empty `decision` string; decision-like prose is never inferred.

The compiler accepts `codex` and `claude` targets; target selection changes only deterministic recipient metadata, not the meaning or authority of the bundle.

Run scoped tests with `pnpm exec tsx --test "packages/resume/**/*.test.ts"`.
