# RFC-001: Event, Session, and Checkpoint Vocabulary

- Status: Normative for v0
- Version: 0.1.0
- Last updated: 2026-08-07

## Abstract

This RFC defines the provider-neutral vocabulary that turns captured work observations into ordered session events and curated checkpoints.

## Identifiers

Every event, session, checkpoint, work item, actor, and space MUST have a stable identifier represented as a non-empty string.

In v0, `event_id` and every `previous_event_id` or checkpoint `event_id` reference MUST match `urn:owc:event:<suffix>`, where the suffix contains only ASCII letters, digits, `.`, `_`, `:`, or `-`, and the complete identifier is at most 512 characters.

The event URN is the portable core identity contract; its suffix remains opaque and MAY contain a UUID, content-derived identifier, or another collision-resistant value.

Session, checkpoint, work-item, actor, and space identifiers MAY use UUID URNs, content-derived URNs, or another collision-resistant namespace unless their own schema defines a narrower form.

An external provider identifier MUST be stored as provider metadata and MUST NOT replace the commons identifier.

Identifiers MUST be treated as opaque by adapters and user interfaces.

## Actor

An actor is the principal associated with an event and has a kind of `human`, `agent`, `service`, or `device`.

The actor field records attribution asserted by the recorder; it is not proof of legal identity.

An agent name or model MAY appear in namespaced extensions, but the core actor identifier MUST remain independent of a specific vendor.

## Provider

A provider is the external or native source from which an observation was obtained.

Provider metadata includes a stable provider name and MAY include adapter version, provider version, external session identifier, and external event identifier.

Entire MAY be the provider for the first adapter, but a conforming event MUST remain meaningful after all provider metadata is removed.

## Event

An event is an immutable normalized observation associated with one session.

Each event contains a stable identifier, type, recorded timestamp, actor, space, session, sequence number, previous-event reference, provider metadata, subject, payload reference, sensitivity, and retention declaration.

The event identifier is an opaque identity and is not itself a content-integrity claim; archive entry digests provide integrity for serialized event bytes.

The payload digest covers either the RFC 8785 canonical bytes of an inline JSON value or the exact bytes of the referenced archive entry.

Events MUST NOT be changed in place; a correction is a later event that refers to or supersedes the incorrect observation.

## Event types

v0 defines the following core event types.

- `session.started` declares that local capture began and MAY include a visible objective supplied by the operator.
- `context.declared` records visible, authorized context presented to an actor.
- `tool.observed` records an authorized observation of a tool request or result without claiming that the tool behaved correctly.
- `artifact.changed` records an observed artifact state or patch digest.
- `evidence.observed` records evidence emitted by an identified verifier for an identified subject digest.
- `human.intervened` records a visible correction, decision, approval, or stop instruction supplied by a human.
- `checkpoint.requested` records the request to curate a checkpoint from a session prefix.
- `session.ended` records a normal, interrupted, failed, or unknown session termination.

The eight names above are the complete v0 core set; an unnamespaced name outside that set is not v0-conformant even if it has the same dotted syntax.

An extension event type MUST have the form `<reverse-dns>/<dotted-type>`, for example `org.example.capture/session.annotated`.

The reverse-DNS namespace MUST contain at least two lowercase DNS-style labels, and the dotted type MUST contain at least two lowercase segments beginning with a letter; a v0 verifier MUST reject every other extension spelling.

## Ordering and causality

Session sequence numbers start at zero and increase by one for each durable normalized event.

The first event MUST have a null `previous_event_id`; every later event MUST reference the immediately preceding event in that session.

Recorded timestamps are descriptive and MUST NOT be used as the sole ordering mechanism.

Concurrent or external causality MAY be represented in namespaced extensions in v0; a future protocol version may standardize a richer causal graph.

Adapters that receive incomplete provider history MUST preserve a declared gap rather than renumber observations as if the history were complete.

## Session

A session is the ordered collection of normalized events that share one session identifier.

A session MAY be open, ended, interrupted, or recovered after recorder failure.

A session does not require a transcript, and the absence of a transcript MUST NOT make a checkpoint unverifiable.

One provider session MAY map to one commons session in v0; merging multiple provider sessions into one session is outside the normative v0 behavior.

## Subject and payload

The subject identifies the entity primarily described by an event, such as a session, artifact, command, work item, or evidence result.

The payload contains observation details and is either inline JSON or an archive-relative path.

Inline JSON payloads MUST have a matching canonical SHA-256 digest.

Path payloads MUST have a digest matching the exact referenced bytes and MUST satisfy the archive path rules in RFC-002.

Payload data remains untrusted even after its digest and archive signature validate.

## Artifact

An artifact is a byte sequence or logical object produced, inspected, or changed during work.

An artifact reference contains a relative path, media type, SHA-256 digest, byte length, and role.

A digest proves byte identity, not authorship, safety, or semantic correctness.

## Claim and evidence

A claim is an assertion such as “the tests pass,” “the migration is safe,” or “the task is complete.”

Evidence is an observation from a named verifier about a named subject digest and procedure.

The v0 evidence identity fields are `evidence_id`, `kind`, `issuer`, `subject_digest`, `result`, and `observed_at`; `kind` names the verification procedure or procedure class, and `result` is `passed`, `failed`, or `unknown`.

A checkpoint MAY carry the strict evidence record inline without a source object.

When checkpoint evidence includes `source`, that path and digest MUST resolve to a manifest entry with role `evidence` and media type `application/json`, the entry MUST satisfy the bundled v0 evidence schema, and all six evidence identity fields MUST match exactly.

Every manifest entry with role `evidence` MUST satisfy the evidence schema even when no checkpoint cites it.

Claims and evidence MUST remain separate even when emitted by the same provider.

A visible agent statement MAY become a claim but MUST NOT become independent evidence unless a verifier observation is also captured.

## Checkpoint

A checkpoint is an immutable curated handoff that selects a session prefix, exact Git state, relevant artifacts, evidence, exclusions, open questions, and one next action.

A checkpoint MUST reference at least one event and exactly one Git-state object.

A checkpoint MAY have zero or more parent checkpoints; parent references MUST form an acyclic graph.

Checkpoint parents express handoff lineage and MUST NOT be inferred from creation timestamps.

A checkpoint MUST preserve evidence gaps and unknowns rather than implying completion.

A checkpoint MUST identify every capture provider involved while keeping its content provider-neutral.

## Exclusion

An exclusion states that a category of material was intentionally omitted and gives a reason and policy identifier.

Every v0 checkpoint MUST include a `raw-transcript` exclusion; under the default policy it states that raw transcript bytes were not imported into the checkpoint or portable archive.

An explicitly authorized future extension that retains an encrypted transcript copy MUST keep those bytes outside the normative checkpoint and resume inputs and MUST still declare that exclusion boundary.

The exclusion does not claim that a provider never retained a transcript or that copies outside the archive were deleted.

An exclusion is part of the signed handoff and MUST NOT be interpreted as proof that omitted material never existed.

## Next action

The next action is a concise operator-curated statement of the next bounded step.

It MUST cite at least one source object in the archive and MUST NOT contain executable instructions that a resume compiler runs automatically.

An implementation MAY allow a human to revise the next action only by creating a new checkpoint or signed derivative.

## Unknown and unsupported values

Absence means “not recorded” and MUST NOT be rendered as false, successful, denied, or complete.

Adapters SHOULD use an extension to describe a provider capability gap when the distinction between unavailable and unobserved matters.

No model call, fuzzy match, or heuristic identity reconstruction may fill a normative field.

## v0 compatibility note

This clarification retains the existing `urn:owc:event:*` identity contract and all eight published core event names, but it intentionally rejects pre-release implementations that accepted arbitrary dotted event types.

An existing custom dotted type MUST migrate to the reverse-DNS extension form before it is archived, and validators using the earlier broad dotted-name expression MUST update their event-type allowlist.

Existing strict inline checkpoint evidence remains valid; adding a `source` is optional.
