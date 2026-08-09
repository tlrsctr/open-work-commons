# Open Work Commons contribution contract

## Mission

Build public infrastructure that people can run locally, inspect, export, replace, and continue using if every contributing company disappears.

## Invariants

- Entire and every other external tool is a replaceable adapter.
- The portable archive and conformance fixtures are the interoperability boundary.
- A signature proves which key asserted bytes and that they did not change; it does not prove an assertion is true.
- Agent claims and external evidence are different object types.
- Open Work Commons transcript import and archive inclusion are off by default; upstream providers may retain their own copies, which adapters must disclose.
- Never request, persist, or imply access to hidden chain-of-thought.
- Authorization and redaction happen before durable writes or retrieval.
- Unknown information remains explicit; do not infer identifiers, authority, test results, or completion.
- The same normative inputs must produce the same payload digest.
- A verifier must work without network access or a vendor account.

## Engineering

- Keep normative behavior in focused packages under `packages/`; adapters may translate but never redefine the archive, verification, or conformance contracts.
- Add valid, invalid, and malicious conformance fixtures for every normative schema change.
- Preserve forward compatibility through explicit schema versions and namespaced extensions.
- Do not add a network dependency to archive verification.
- Do not add telemetry, hosted authentication, or model calls to the core.
- Use one prose paragraph per source line in Markdown.
- Run `pnpm check` before handoff.

## Parallel work

- One integrator owns root configuration, lockfiles, shared exports, release records, and Plane reconciliation.
- Contributors receive exclusive writable paths.
- Generated schemas and fixtures are integration boundaries; propose changes rather than editing across another workstream.
- A task is complete only with the declared tests and evidence.
