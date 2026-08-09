# Synthetic approved-handoff example

This directory contains fictional, non-secret input for the v0 two-phase handoff flow.

`operator-plan.json` is the information the operator intends to preserve. It binds the provider and checkpoint identity, work objective, constraints, explicit decisions, open questions, next action, sensitivity, and retention class.

`entire-checkpoint-detail.sanitized.json` models caller-supplied Entire 0.9 checkpoint-detail JSON. Its `SYNTHETIC_EXCLUDED_*` values are deliberate test canaries: inspection and archive creation must exclude them. The minimal structural provider projection may retain only provider/checkpoint identity, timestamps, external session identifiers, metadata-availability flags, and explicit import gaps.

No archive output is committed because every fresh workspace creates its own Ed25519 device identity. Follow the [developer-preview quickstart](../../docs/release/quickstart.md) to inspect, approve, sign, verify, and compile a resume bundle locally.
