import { timingSafeEqual } from "node:crypto";

import {
  importEntireCheckpointDetail,
  type OwcCandidateGap,
  type OwcCheckpointCandidate,
} from "../../adapters/entire/src/index.js";
import {
  canonicalJsonBytes,
  parseJsonSafely,
  sha256,
  verifyLogicalArchive,
  type ArchiveEntryRole,
  type Digest,
  type LogicalArchive,
} from "../../archive/src/index.js";

import { buildStoreWritePlan } from "./store-plan.js";
import {
  HandoffError,
  type ApprovedHandoff,
  type CreateApprovedHandoffInput,
  type HandoffArchiveEntryReview,
  type HandoffArtifactReview,
  type HandoffCheckpoint,
  type HandoffExclusion,
  type HandoffInspection,
  type InspectHandoffInput,
  type NormalizedHandoffEvent,
  type NormalizedOperatorHandoffPlan,
  type SafeEntireCheckpointProjection,
} from "./types.js";
import {
  assertRfc3339,
  isDigest,
  normalizePlan,
  validateCapturedGitState,
  validateSigningIdentity,
  type ValidatedSignerIdentity,
} from "./validation.js";

const PROJECTION_PATH = "extensions/entire-checkpoint-projection.json";
const GIT_STATE_PATH = "state/git-state.json";
const EVENT_MEDIA_TYPE = "application/json";
const CHECKPOINT_MEDIA_TYPE = "application/json";
const GIT_STATE_MEDIA_TYPE = "application/json";
const PROJECTION_MEDIA_TYPE =
  "application/vnd.openworkcommons.entire-checkpoint-projection+json";
const JSON_LIMITS = {
  maxDepth: 64,
  maxStringBytes: 1024 * 1024,
} as const;

const ARCHIVE_EXTENSIONS = (basisDigest: Digest) => ({
  "openworkcommons.org/handoff_basis_digest": basisDigest,
  "openworkcommons.org/approval_protocol": "exact-digest-v0.1",
});

const EXCLUSIONS: readonly HandoffExclusion[] = [
  {
    category: "raw-transcript",
    reason:
      "Provider transcripts, prompts, responses, and hidden reasoning are never projected or archived.",
    policy: "owc-v0-default-deny",
  },
  {
    category: "provider-summaries",
    reason:
      "Provider-authored intent, outcome, friction, open-item, and learning prose is excluded from this operator-authored handoff.",
    policy: "owc-v0-default-deny",
  },
  {
    category: "provider-messages",
    reason: "Provider-authored checkpoint and session messages are excluded.",
    policy: "owc-v0-default-deny",
  },
  {
    category: "provider-reported-files",
    reason:
      "Provider-reported file lists are not treated as exact Git state and are excluded.",
    policy: "owc-v0-default-deny",
  },
  {
    category: "unknown-provider-fields",
    reason:
      "Fields outside the minimal Entire 0.9 structural allowlist are excluded.",
    policy: "owc-v0-default-deny",
  },
];

interface ProposedEntry {
  readonly path: string;
  readonly mediaType: string;
  readonly role: ArchiveEntryRole;
  readonly bytes: Uint8Array;
  readonly digest: Digest;
}

interface PreparedHandoff {
  readonly inspection: HandoffInspection;
  readonly entries: readonly ProposedEntry[];
  readonly checkpoint: HandoffCheckpoint;
  readonly events: readonly NormalizedHandoffEvent[];
  readonly rootCheckpointPath: string;
  readonly limits: {
    readonly entry_count: number;
    readonly expanded_bytes: number;
    readonly max_entry_bytes: number;
  };
  readonly extensions: Readonly<Record<string, unknown>>;
}

/**
 * Pure phase one. It imports only caller-supplied JSON and does no I/O,
 * signing, provider command invocation, model call, or durable write.
 */
export function inspectHandoff(input: InspectHandoffInput): HandoffInspection {
  return prepareHandoff(input).inspection;
}

/**
 * Phase two recomputes the full proposal and signs only if the caller presents
 * the exact phase-one digest. The signing capability never exposes private
 * bytes to this package.
 */
export function createApprovedHandoff(
  input: CreateApprovedHandoffInput,
): ApprovedHandoff {
  const prepared = prepareHandoff(input);
  requireExactApproval(
    input.approvalDigest,
    prepared.inspection.approvalDigest,
  );

  let archive: LogicalArchive;
  try {
    const signedArchive = input.signingIdentity.createSignedArchive({
      archiveId: prepared.inspection.identifiers.archiveId,
      createdAt: prepared.inspection.capturedAt,
      rootCheckpoint: {
        checkpointId: prepared.inspection.identifiers.checkpointId,
        path: prepared.rootCheckpointPath,
      },
      entries: prepared.entries.map((entry) => ({
        path: entry.path,
        mediaType: entry.mediaType,
        role: entry.role,
        requiredForVerification: true,
        bytes: new Uint8Array(entry.bytes),
      })),
      exclusions: EXCLUSIONS.map((item) => ({ ...item })),
      limits: prepared.limits,
      extensions: prepared.extensions,
    });
    archive = cloneLogicalArchive(signedArchive);
  } catch {
    throw archiveFailure();
  }

  assertSignedArchiveMatchesProposal(archive, prepared);
  const verification = verifyLogicalArchive(archive, {
    trustedSignerFingerprints: [prepared.inspection.signer.fingerprint],
  });
  if (
    !verification.integrity.valid ||
    !verification.signer.signatureValid ||
    !verification.signer.trusted ||
    verification.signer.trust !== "trusted" ||
    verification.signer.keyId !== prepared.inspection.signer.keyId ||
    verification.signer.fingerprint !==
      prepared.inspection.signer.fingerprint ||
    verification.archive.archiveId !==
      prepared.inspection.identifiers.archiveId ||
    verification.archive.rootCheckpointId !==
      prepared.inspection.identifiers.checkpointId ||
    verification.archive.payloadDigest !==
      prepared.inspection.proposedArchive.payloadDigest ||
    verification.archive.entryCount !== prepared.entries.length
  ) {
    throw archiveFailure();
  }

  const storeWritePlan = buildStoreWritePlan(
    archive,
    prepared.events,
    prepared.inspection.approvalDigest,
    prepared.inspection.identifiers.archiveId,
  );
  return {
    inspection: prepared.inspection,
    archive,
    verification,
    checkpoint: cloneJson(prepared.checkpoint),
    events: prepared.events.map((event) => cloneJson(event)),
    storeWritePlan,
  };
}

function prepareHandoff(input: InspectHandoffInput): PreparedHandoff {
  if (!input || typeof input !== "object") {
    throw new HandoffError("invalid_input", "A handoff input is required.");
  }
  if (typeof input.entireCheckpointDetailJson !== "string") {
    throw new HandoffError(
      "invalid_input",
      "Caller-supplied Entire checkpoint-detail JSON is required.",
    );
  }
  assertRfc3339(input.capturedAt);
  const plan = normalizePlan(input.plan);
  const signer = validateSigningIdentity(input.signingIdentity);
  const artifacts = validateCapturedGitState(input.git, input.capturedAt);
  const gitStateBytes = new Uint8Array(input.git.stateBytes);
  if (sha256(gitStateBytes) !== input.git.stateDigest) {
    throw new HandoffError(
      "git_state_invalid",
      "The captured Git state changed during handoff inspection.",
    );
  }
  const gitState = cloneJson(input.git.state);
  if (!sameBytes(canonicalJsonBytes(gitState), gitStateBytes)) {
    throw new HandoffError(
      "git_state_invalid",
      "The captured Git state changed during handoff inspection.",
    );
  }
  const imported = importEntireCheckpointDetail(
    input.entireCheckpointDetailJson,
    { providerVersion: plan.source.providerVersion },
  );
  if (imported.status !== "ok") {
    throw new HandoffError(
      "entire_import_invalid",
      "The caller-supplied Entire checkpoint-detail JSON did not pass the bounded importer.",
    );
  }
  if (
    imported.sourceFormat !== "entire-checkpoint-detail-v0.9" ||
    imported.checkpoints.length !== 1
  ) {
    throw new HandoffError(
      "blocking_import_gap",
      "The import is not a complete Entire 0.9 checkpoint-detail projection.",
    );
  }
  const importedCheckpoint = imported.checkpoints[0];
  if (!importedCheckpoint || importedCheckpoint.completeness !== "metadata") {
    throw new HandoffError(
      "blocking_import_gap",
      "The import lacks the checkpoint-detail metadata boundary required by v0.",
    );
  }
  if (
    importedCheckpoint.source.provider !== plan.source.provider ||
    importedCheckpoint.source.providerVersion !== plan.source.providerVersion
  ) {
    throw new HandoffError(
      "provider_mismatch",
      "The imported checkpoint provider does not match the approved plan source.",
    );
  }
  if (
    importedCheckpoint.source.externalCheckpointId !==
    plan.source.externalCheckpointId
  ) {
    throw new HandoffError(
      "external_checkpoint_mismatch",
      "The imported checkpoint ID does not match the operator-bound external checkpoint ID.",
    );
  }

  const importedGaps = collectImportedGaps(importedCheckpoint, imported.events);
  if (importedGaps.includes("checkpoint_detail_not_imported")) {
    throw new HandoffError(
      "blocking_import_gap",
      "The imported candidate contains a gap that prevents truthful v0 construction.",
    );
  }
  const projection = projectEntireCheckpoint(
    importedCheckpoint,
    importedGaps,
    plan.source.providerVersion,
  );

  const handoffBasisDigest = sha256(
    canonicalJsonBytes({
      protocol: "open-work-commons-handoff-basis-v0.1",
      captured_at: input.capturedAt,
      operator_plan: plan,
      provider_projection: projection,
      git_state_digest: input.git.stateDigest,
      git_artifacts: artifacts.map((artifact) => ({
        path: artifact.path,
        media_type: artifact.mediaType,
        digest: artifact.digest,
        byte_length: artifact.byteLength,
        role: artifact.role,
      })),
    }),
  );
  const checkpointId = urn("checkpoint", handoffBasisDigest);
  const sessionId = urn("session", taggedDigest("session", handoffBasisDigest));
  const events = buildEvents(
    plan,
    input.capturedAt,
    checkpointId,
    sessionId,
    handoffBasisDigest,
    importedGaps,
  );
  const eventEntries = events.map((event, sequence): ProposedEntry => {
    const bytes = canonicalJsonBytes(event);
    return {
      path: eventPath(sequence, event.event_id),
      mediaType: EVENT_MEDIA_TYPE,
      role: "event",
      bytes,
      digest: sha256(bytes),
    };
  });
  const projectionBytes = canonicalJsonBytes(projection);
  const projectionDigest = sha256(projectionBytes);
  const checkpointPath = `checkpoints/${digestHex(handoffBasisDigest)}.json`;
  const checkpoint = buildCheckpoint(
    plan,
    input.capturedAt,
    checkpointId,
    sessionId,
    checkpointPath,
    events,
    eventEntries,
    input.git.stateDigest,
    artifacts,
    projectionDigest,
    importedCheckpoint.externalSessionIds,
    importedGaps,
  );
  const checkpointBytes = canonicalJsonBytes(checkpoint);
  const checkpointDigest = sha256(checkpointBytes);

  const normativeEntries: ProposedEntry[] = [
    ...eventEntries,
    {
      path: checkpointPath,
      mediaType: CHECKPOINT_MEDIA_TYPE,
      role: "checkpoint",
      bytes: checkpointBytes,
      digest: checkpointDigest,
    },
    {
      path: GIT_STATE_PATH,
      mediaType: GIT_STATE_MEDIA_TYPE,
      role: "git-state",
      bytes: gitStateBytes,
      digest: input.git.stateDigest,
    },
    {
      path: PROJECTION_PATH,
      mediaType: PROJECTION_MEDIA_TYPE,
      role: "extension",
      bytes: projectionBytes,
      digest: projectionDigest,
    },
    ...artifactEntries(input, artifacts),
  ];
  const entries = normativeEntries.sort((left, right) =>
    compareStrings(left.path, right.path),
  );
  assertUniquePaths(entries);

  const entryReviews = entries.map(toEntryReview);
  const expandedBytes = entries.reduce(
    (total, entry) => total + entry.bytes.byteLength,
    0,
  );
  const maxEntryBytes = entries.reduce(
    (maximum, entry) => Math.max(maximum, entry.bytes.byteLength),
    0,
  );
  const limits = {
    entry_count: entries.length,
    expanded_bytes: expandedBytes,
    max_entry_bytes: maxEntryBytes,
  };
  const archiveId = urn(
    "archive",
    sha256(
      canonicalJsonBytes({
        protocol: "open-work-commons-archive-identity-v0.1",
        checkpoint_id: checkpointId,
        entries: entryReviews,
        signer: signer,
      }),
    ),
  );
  const rootCheckpoint = {
    checkpointId,
    path: checkpointPath,
    digest: checkpointDigest,
  };
  const extensions = ARCHIVE_EXTENSIONS(handoffBasisDigest);
  const payloadDigest = proposedPayloadDigest(
    archiveId,
    input.capturedAt,
    rootCheckpoint,
    entryReviews,
    limits,
    signer,
    extensions,
  );
  const gaps = categorizeGaps(importedGaps);

  const reviewWithoutApproval = {
    format: "open-work-commons-handoff-inspection",
    schemaVersion: "0.1",
    handoffBasisDigest,
    capturedAt: input.capturedAt,
    identifiers: {
      archiveId,
      checkpointId,
      sessionId,
      eventIds: events.map((event) => event.event_id),
    },
    signer: {
      keyId: signer.keyId,
      fingerprint: signer.fingerprint,
      publicKey: signer.publicKey,
    },
    included: {
      operatorPlan: plan,
      providerProjection: projection,
      events,
      checkpoint,
      gitState,
      gitStateDigest: input.git.stateDigest,
      artifacts,
    },
    excluded: EXCLUSIONS,
    gaps,
    proposedArchive: {
      rootCheckpoint,
      entries: entryReviews,
      payloadDigest,
      limits: {
        entryCount: limits.entry_count,
        expandedBytes: limits.expanded_bytes,
        maxEntryBytes: limits.max_entry_bytes,
      },
    },
  } as const;
  const approvalDigest = sha256(canonicalJsonBytes(reviewWithoutApproval));
  const inspection = cloneJson({
    ...reviewWithoutApproval,
    approvalDigest,
  }) as HandoffInspection;

  return {
    inspection,
    entries,
    checkpoint,
    events,
    rootCheckpointPath: checkpointPath,
    limits,
    extensions,
  };
}

function projectEntireCheckpoint(
  checkpoint: OwcCheckpointCandidate,
  importedGaps: readonly string[],
  providerVersion: string,
): SafeEntireCheckpointProjection {
  return {
    format: "open-work-commons-entire-checkpoint-projection",
    schema_version: "0.1",
    source: {
      provider: "entire",
      provider_version: providerVersion,
      external_checkpoint_id: checkpoint.source.externalCheckpointId,
    },
    provider_timestamp: checkpoint.providerTimestamp,
    external_session_ids: uniqueSorted(checkpoint.externalSessionIds),
    sessions: checkpoint.sessions.map((session) => ({
      index: session.index,
      metadata_available: session.metadataAvailable,
      external_session_id: session.externalSessionId,
      provider_timestamp: session.providerTimestamp,
      gaps: uniqueSorted(session.gaps),
    })),
    imported_gaps: importedGaps,
    handling: {
      content_trust: "untrusted-provider-output",
      raw_transcripts: "excluded",
      executable: false,
    },
  };
}

function collectImportedGaps(
  checkpoint: OwcCheckpointCandidate,
  events: readonly { readonly gaps: readonly OwcCandidateGap[] }[],
): readonly string[] {
  return uniqueSorted([
    ...checkpoint.gaps,
    ...checkpoint.sessions.flatMap((session) => session.gaps),
    ...events.flatMap((event) => event.gaps),
  ]);
}

function buildEvents(
  plan: NormalizedOperatorHandoffPlan,
  capturedAt: string,
  checkpointId: string,
  sessionId: string,
  basisDigest: Digest,
  importedGaps: readonly string[],
): readonly NormalizedHandoffEvent[] {
  const eventSpecs: readonly {
    readonly eventType: "human.intervened" | "checkpoint.requested";
    readonly payload: Readonly<Record<string, unknown>>;
  }[] = [
    ...plan.decisions.map((decision, index) => ({
      eventType: "human.intervened" as const,
      payload: { decision, decision_index: index },
    })),
    {
      eventType: "checkpoint.requested" as const,
      payload: {
        request: "create-portable-handoff",
        external_checkpoint_id: plan.source.externalCheckpointId,
        work_item_id: plan.work.workItemId,
      },
    },
  ];
  const events: NormalizedHandoffEvent[] = [];
  let previousEventId: string | null = null;
  for (const [sequence, spec] of eventSpecs.entries()) {
    const payloadDigest = sha256(canonicalJsonBytes(spec.payload));
    const eventId = urn(
      "event",
      sha256(
        canonicalJsonBytes({
          protocol: "open-work-commons-operator-event-v0.1",
          handoff_basis_digest: basisDigest,
          event_type: spec.eventType,
          sequence,
          previous_event_id: previousEventId,
          payload_digest: payloadDigest,
        }),
      ),
    );
    events.push({
      schema_version: "0.1",
      event_id: eventId,
      event_type: spec.eventType,
      recorded_at: capturedAt,
      actor: {
        id: plan.actor.id,
        kind: "human",
        ...(plan.actor.displayName === undefined
          ? {}
          : { display_name: plan.actor.displayName }),
      },
      space_id: plan.spaceId,
      session_id: sessionId,
      sequence,
      previous_event_id: previousEventId,
      provider: {
        name: "open-work-commons",
        adapter_version: "handoff-v0.1",
      },
      subject: { kind: "checkpoint", id: checkpointId },
      payload: {
        media_type: "application/json",
        digest: payloadDigest,
        inline: spec.payload,
      },
      sensitivity: plan.sensitivity,
      retention: {
        class: plan.retention.class,
        expires_at: plan.retention.expiresAt,
      },
      extensions: {
        "openworkcommons.org/event_origin": "operator-authored",
        "openworkcommons.org/source_checkpoint": {
          provider: "entire",
          provider_version: plan.source.providerVersion,
          external_checkpoint_id: plan.source.externalCheckpointId,
        },
        "openworkcommons.org/provider_import_gaps": importedGaps,
      },
    });
    previousEventId = eventId;
  }
  return events;
}

function buildCheckpoint(
  plan: NormalizedOperatorHandoffPlan,
  capturedAt: string,
  checkpointId: string,
  sessionId: string,
  checkpointPath: string,
  events: readonly NormalizedHandoffEvent[],
  eventEntries: readonly ProposedEntry[],
  gitStateDigest: Digest,
  artifacts: readonly HandoffArtifactReview[],
  projectionDigest: Digest,
  externalSessionIds: readonly string[],
  importedGaps: readonly string[],
): HandoffCheckpoint {
  const captureProviders =
    externalSessionIds.length === 0
      ? ([{ name: "entire" }] as const)
      : uniqueSorted(externalSessionIds).map((externalSessionId) => ({
          name: "entire" as const,
          external_session_id: externalSessionId,
        }));
  return {
    schema_version: "0.1",
    checkpoint_id: checkpointId,
    created_at: capturedAt,
    session_id: sessionId,
    capture_providers: captureProviders,
    work: {
      work_item_id: plan.work.workItemId,
      title: plan.work.title,
      objective: plan.work.objective,
      constraints: plan.work.constraints,
    },
    parents: [],
    event_refs: eventEntries.map((entry, sequence) => {
      const event = events[sequence];
      if (!event) throw archiveFailure();
      return {
        event_id: event.event_id,
        path: entry.path,
        digest: entry.digest,
      };
    }),
    git_state: { path: GIT_STATE_PATH, digest: gitStateDigest },
    artifacts: artifacts.map((artifact) => ({
      path: artifact.path,
      digest: artifact.digest,
      media_type: artifact.mediaType,
      role: artifact.role,
      byte_length: artifact.byteLength,
    })),
    claims: [],
    evidence: [],
    open_questions: plan.openQuestions,
    exclusions: EXCLUSIONS,
    next_action: {
      statement: plan.nextAction,
      source_paths: [checkpointPath],
    },
    extensions: {
      "openworkcommons.org/source_checkpoint": {
        provider: "entire",
        provider_version: plan.source.providerVersion,
        external_checkpoint_id: plan.source.externalCheckpointId,
      },
      "openworkcommons.org/provider_projection": {
        path: PROJECTION_PATH,
        digest: projectionDigest,
      },
      "openworkcommons.org/provider_import_gaps": importedGaps,
      "openworkcommons.org/event_boundary": "operator-authored-events-only",
    },
  };
}

function artifactEntries(
  input: InspectHandoffInput,
  artifacts: readonly HandoffArtifactReview[],
): readonly ProposedEntry[] {
  const byPath = new Map(
    [
      ...(input.git.patchArtifact === null ? [] : [input.git.patchArtifact]),
      ...input.git.untrackedArtifacts,
    ].map((artifact) => [artifact.path, artifact]),
  );
  return artifacts.map((review) => {
    const artifact = byPath.get(review.path);
    if (!artifact) {
      throw new HandoffError(
        "git_state_invalid",
        "An exact Git artifact disappeared during handoff inspection.",
      );
    }
    const bytes = new Uint8Array(artifact.bytes);
    if (
      bytes.byteLength !== review.byteLength ||
      sha256(bytes) !== review.digest
    ) {
      throw new HandoffError(
        "git_state_invalid",
        "An exact Git artifact changed during handoff inspection.",
      );
    }
    return {
      path: review.path,
      mediaType: review.mediaType,
      role: "artifact",
      bytes,
      digest: review.digest,
    };
  });
}

function proposedPayloadDigest(
  archiveId: string,
  createdAt: string,
  rootCheckpoint: {
    readonly checkpointId: string;
    readonly path: string;
    readonly digest: Digest;
  },
  entries: readonly HandoffArchiveEntryReview[],
  limits: {
    readonly entry_count: number;
    readonly expanded_bytes: number;
    readonly max_entry_bytes: number;
  },
  signer: ValidatedSignerIdentity,
  extensions: Readonly<Record<string, unknown>>,
): Digest {
  return sha256(
    canonicalJsonBytes({
      format: "open-work-commons-portable-archive",
      schema_version: "0.1",
      archive_id: archiveId,
      created_at: createdAt,
      root_checkpoint: {
        checkpoint_id: rootCheckpoint.checkpointId,
        path: rootCheckpoint.path,
        digest: rootCheckpoint.digest,
      },
      entries: entries.map((entry) => ({
        path: entry.path,
        media_type: entry.mediaType,
        role: entry.role,
        byte_length: entry.byteLength,
        digest: entry.digest,
        required_for_verification: true,
      })),
      exclusions: EXCLUSIONS,
      limits,
      signature: {
        canonicalization: "RFC8785",
        digest_algorithm: "sha256",
        signature_algorithm: "ed25519",
        key_id: signer.keyId,
        public_key: signer.publicKey,
      },
      extensions,
    }),
  );
}

function categorizeGaps(
  imported: readonly string[],
): HandoffInspection["gaps"] {
  const resolved = imported.includes("authorization_and_redaction_required")
    ? ["authorization_and_redaction_required"]
    : [];
  return {
    imported,
    resolvedByExactApproval: resolved,
    residual: imported.filter((gap) => !resolved.includes(gap)),
    blocking: [],
  };
}

function toEntryReview(entry: ProposedEntry): HandoffArchiveEntryReview {
  return {
    path: entry.path,
    mediaType: entry.mediaType,
    role: entry.role as HandoffArchiveEntryReview["role"],
    digest: entry.digest,
    byteLength: entry.bytes.byteLength,
    requiredForVerification: true,
  };
}

function assertSignedArchiveMatchesProposal(
  archive: LogicalArchive,
  prepared: PreparedHandoff,
): void {
  if (
    !archive ||
    !(archive.manifestBytes instanceof Uint8Array) ||
    !Array.isArray(archive.entries) ||
    archive.entries.length !== prepared.entries.length
  ) {
    throw archiveFailure();
  }
  const expected = new Map(
    prepared.entries.map((entry) => [entry.path, entry]),
  );
  for (const entry of archive.entries) {
    const proposed = expected.get(entry.path);
    if (
      !proposed ||
      entry.kind !== "file" ||
      !sameBytes(entry.bytes, proposed.bytes)
    ) {
      throw archiveFailure();
    }
    expected.delete(entry.path);
  }
  if (expected.size !== 0) throw archiveFailure();

  let manifest: Record<string, unknown>;
  try {
    const parsed = parseJsonSafely(archive.manifestBytes, JSON_LIMITS);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError("invalid");
    }
    manifest = parsed as Record<string, unknown>;
  } catch {
    throw archiveFailure();
  }
  const signature = manifest.signature;
  if (!signature || typeof signature !== "object" || Array.isArray(signature)) {
    throw archiveFailure();
  }
  const signatureRecord = signature as Record<string, unknown>;
  if (
    manifest.archive_id !== prepared.inspection.identifiers.archiveId ||
    manifest.created_at !== prepared.inspection.capturedAt ||
    signatureRecord.key_id !== prepared.inspection.signer.keyId ||
    signatureRecord.public_key !== prepared.inspection.signer.publicKey ||
    signatureRecord.payload_digest !==
      prepared.inspection.proposedArchive.payloadDigest
  ) {
    throw archiveFailure();
  }
}

function requireExactApproval(provided: unknown, expected: Digest): void {
  if (!isDigest(provided)) {
    throw new HandoffError(
      "approval_mismatch",
      "An exact handoff inspection approval digest is required.",
    );
  }
  const left = Buffer.from(provided, "utf8");
  const right = Buffer.from(expected, "utf8");
  if (left.byteLength !== right.byteLength || !timingSafeEqual(left, right)) {
    throw new HandoffError(
      "approval_mismatch",
      "The supplied approval digest does not match the recomputed handoff proposal.",
    );
  }
}

function assertUniquePaths(entries: readonly ProposedEntry[]): void {
  if (new Set(entries.map((entry) => entry.path)).size !== entries.length) {
    throw new HandoffError(
      "git_state_invalid",
      "A captured Git artifact collides with a normative handoff archive path.",
    );
  }
}

function eventPath(sequence: number, eventId: string): string {
  const hex = eventId.slice("urn:owc:event:".length);
  return `events/${sequence.toString().padStart(4, "0")}-${hex}.json`;
}

function urn(
  kind: "archive" | "checkpoint" | "event" | "session",
  digest: Digest,
): string {
  return `urn:owc:${kind}:${digestHex(digest)}`;
}

function taggedDigest(tag: string, digest: Digest): Digest {
  return sha256(canonicalJsonBytes({ tag, digest }));
}

function digestHex(digest: Digest): string {
  return digest.slice("sha256:".length);
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareStrings);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function cloneJson<T>(value: T): T {
  return JSON.parse(new TextDecoder().decode(canonicalJsonBytes(value))) as T;
}

/** Break every byte alias retained by an injected signing capability. */
function cloneLogicalArchive(value: LogicalArchive): LogicalArchive {
  if (
    !value ||
    !(value.manifestBytes instanceof Uint8Array) ||
    !Array.isArray(value.entries)
  ) {
    throw archiveFailure();
  }
  return {
    manifestBytes: new Uint8Array(value.manifestBytes),
    entries: value.entries.map((entry) => {
      if (
        !entry ||
        typeof entry.path !== "string" ||
        !(entry.bytes instanceof Uint8Array)
      ) {
        throw archiveFailure();
      }
      return {
        path: entry.path,
        bytes: new Uint8Array(entry.bytes),
        ...(entry.kind === undefined ? {} : { kind: entry.kind }),
      };
    }),
  };
}

function archiveFailure(): HandoffError {
  return new HandoffError(
    "archive_construction_failed",
    "The signing capability did not produce the exact approved, verifiable archive.",
  );
}
