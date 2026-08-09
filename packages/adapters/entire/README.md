# Entire adapter checkpoint boundary

This adapter probes only `entire --version`, machine-readable `agent-help ... --json`, and `entire status --json` during inspection.

Each default-runner probe has a bounded execution deadline, bounded combined output, a SIGTERM grace period, and SIGKILL escalation with forced settlement. Failed probes discard captured bytes and expose only fixed adapter diagnostics; raw stdout, stderr, operating-system errors, and paths never enter a capability report.

Entire 0.9 exposes structured checkpoint listing through `entire checkpoint list --json` and metadata-only detail through `entire checkpoint explain <id> --json`, but the implementation may discover or fetch remote checkpoint refs even though the commands do not mutate checkpoint content.

Strict-local discovery therefore returns `provider_cli_may_fetch_remote_checkpoint_data` and does not invoke either checkpoint command.

An operator or a future network-authorized boundary may supply previously exported JSON to `importEntireCheckpointList` and `importEntireCheckpointDetail`.

The import functions are pure allowlist projections: unknown fields, transcript fields, prompts, responses, provider error text, absolute paths, and traversal paths never enter the returned candidates.

Returned text is marked as an untrusted provider assertion and requires authorization and redaction before any durable write.

The adapter deliberately leaves OWC event type, OWC identifiers, sequence, previous-event link, payload digest, exact Git state, checkpoint lineage, work definition, and next action unresolved.

Entire search is not used because it is a remote authenticated service, and transcript, raw-transcript, full, generate, login, auth, API, and mutation commands are outside this adapter.
