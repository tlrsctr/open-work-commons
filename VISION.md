# Open Work Commons vision

## The right we are building

People should be able to inspect, move, continue, and delete the copies of durable work state under their control without asking an employer, model vendor, project-management vendor, or hosting company for permission.

Software work is the first proving ground because its artifacts and acceptance tests are unusually concrete. The intended destination is broader: open primitives for work, learning, research, care, creative practice, and civic collaboration that remain owned and governable by the people who create them.

## Constitutional principles

- Exit: every durable object has a documented export and an independently implementable format.
- Local operation: a person can perform essential reads, verification, and recovery without an account or network.
- Consent before capture: authorization, sensitivity, redaction, retention, and audience are decided before durable storage.
- Minimum sufficient memory: the commons preserves what makes work continuable and accountable, not surveillance exhaust by default.
- Provenance without mythology: the system distinguishes observations, claims, evidence, decisions, approvals, and outcomes.
- Replaceable institutions: trackers, agents, editors, hosts, indexes, and user interfaces are projections or adapters rather than owners of truth.
- Human authority: automated systems cannot infer identity, permission, completion, or legitimacy.
- Verifiable interoperability: compatibility is demonstrated by schemas, fixtures, independent implementations, and reproducible tests.
- Neutral stewardship: successful shared protocols should move to governance that no single employer or vendor can unilaterally control.

## Architecture path

### Layer 1: portable work checkpoint

Capture a bounded session, bind it to exact artifacts and evidence, sign it, verify it offline, and resume elsewhere. This is the v0 proof currently implemented in this repository.

### Layer 2: local context graph

Link checkpoints, objectives, decisions, people, agents, documents, evidence, outcomes, and revisions in a queryable local graph. Plane, Git, Entire, documents, and future tools become deterministic adapters and views.

### Layer 3: cooperative spaces

Let people selectively share signed objects into team, research, community, or civic spaces while preserving local copies, explicit authority, revocation limits, retention policy, and auditability.

### Layer 4: plural public infrastructure

Support multiple interoperating implementations, self-hosted and cooperative services, public-interest registries, portable reputation or contribution records chosen by their subjects, and governance that can outlive any founding company.

Each layer must remain useful without the next one. No hosted graph or federation is allowed to become a prerequisite for verifying a Layer 1 archive.

## Relationship to current tools

Git remains the portable snapshot and code-distribution boundary.

Entire is the pragmatic first capture adapter because its CLI is open source and already supports multiple coding agents. It is neither the canonical schema nor a required hosted authority.

DeltaDB represents a possible future hot-state layer for continuously changing, collaborative work. Open Work Commons does not wait for it or imitate a private interface; a future live-work adapter must cross the same consent and export boundaries.

Plane is a useful human planning projection. It owns operational workflow state in a deployment, while the public issue specification and protocol remain portable.

Agent vendors consume bounded context and emit attributed observations. They do not own the person's durable work graph.

## Proof before platform

The project earns the right to expand only by proving increasingly difficult user outcomes:

1. A fresh agent can continue a seeded task from a verified archive without its original transcript.
2. A second implementation independently verifies the same archive and produces compatible results.
3. A local graph reduces missed constraints and repeated questions on real work without leaking private context.
4. Two people can exchange selected work objects while retaining meaningful exit and deletion choices.
5. Multiple implementations can interoperate without one service becoming the identity or availability root.

The project should resist generic ontology builders, autonomous status management, permanent raw capture, speculative federation, and a feature-complete Git or CRDT replacement until a smaller proof requires them.

## What success looks like

The commons succeeds when leaving a tool becomes boring: export, verify, switch, continue. A person's history remains intelligible; evidence keeps its source; private material stays bounded; collaborators can build new views without asking a platform owner; and no company can turn accumulated work context into an irreversible dependency.
