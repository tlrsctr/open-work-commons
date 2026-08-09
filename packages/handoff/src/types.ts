import type {
  ArchiveVerificationResult,
  Digest,
  LogicalArchive,
} from "../../archive/src/index.js";
import type {
  CapturedGitState,
  GitStateV0,
} from "../../git-state/src/index.js";
import type { DeviceSigningIdentity } from "../../identity/src/index.js";
import type {
  BlobWriteResult,
  EventAppendResult,
  NormalizedEventEnvelope,
  StorePolicy,
} from "../../store/src/index.js";

export type HandoffSensitivity =
  "public" | "internal" | "private" | "restricted";

export type HandoffRetentionClass =
  "ephemeral" | "checkpoint" | "archive" | "legal-hold";

/**
 * Every text value in this plan is operator-authored. Provider summaries and
 * transcripts are deliberately absent from the type and rejected at runtime.
 */
export interface OperatorHandoffPlan {
  readonly source: {
    readonly provider: "entire";
    readonly providerVersion: string;
    readonly externalCheckpointId: string;
  };
  readonly actor: {
    readonly id: string;
    readonly displayName?: string;
  };
  readonly spaceId: string;
  readonly work: {
    readonly workItemId: string;
    readonly title: string;
    readonly objective: string;
    readonly constraints: readonly string[];
  };
  readonly decisions?: readonly string[];
  readonly openQuestions?: readonly string[];
  readonly nextAction: string;
  readonly sensitivity: HandoffSensitivity;
  readonly retention: {
    readonly class: HandoffRetentionClass;
    readonly expiresAt: string | null;
  };
}

export interface NormalizedOperatorHandoffPlan {
  readonly source: {
    readonly provider: "entire";
    readonly providerVersion: string;
    readonly externalCheckpointId: string;
  };
  readonly actor: {
    readonly id: string;
    readonly displayName?: string;
  };
  readonly spaceId: string;
  readonly work: {
    readonly workItemId: string;
    readonly title: string;
    readonly objective: string;
    readonly constraints: readonly string[];
  };
  readonly decisions: readonly string[];
  readonly openQuestions: readonly string[];
  readonly nextAction: string;
  readonly sensitivity: HandoffSensitivity;
  readonly retention: {
    readonly class: HandoffRetentionClass;
    readonly expiresAt: string | null;
  };
}

export interface InspectHandoffInput {
  /** Caller-supplied output from Entire 0.9 `checkpoint explain --json`. */
  readonly entireCheckpointDetailJson: string;
  readonly plan: OperatorHandoffPlan;
  readonly capturedAt: string;
  readonly git: CapturedGitState;
  /** Inspection reads only publicIdentity and never calls either signer. */
  readonly signingIdentity: DeviceSigningIdentity;
}

export interface CreateApprovedHandoffInput extends InspectHandoffInput {
  readonly approvalDigest: Digest;
}

export interface SafeEntireSessionProjection {
  readonly index: number;
  readonly metadata_available: boolean;
  readonly external_session_id: string | null;
  readonly provider_timestamp: string | null;
  readonly gaps: readonly string[];
}

/** Minimal allowlisted projection. No provider-authored prose is represented. */
export interface SafeEntireCheckpointProjection {
  readonly format: "open-work-commons-entire-checkpoint-projection";
  readonly schema_version: "0.1";
  readonly source: {
    readonly provider: "entire";
    readonly provider_version: string;
    readonly external_checkpoint_id: string;
  };
  readonly provider_timestamp: string | null;
  readonly external_session_ids: readonly string[];
  readonly sessions: readonly SafeEntireSessionProjection[];
  readonly imported_gaps: readonly string[];
  readonly handling: {
    readonly content_trust: "untrusted-provider-output";
    readonly raw_transcripts: "excluded";
    readonly executable: false;
  };
}

export type NormalizedHandoffEvent = NormalizedEventEnvelope;

export interface HandoffCheckpoint {
  readonly schema_version: "0.1";
  readonly checkpoint_id: string;
  readonly created_at: string;
  readonly session_id: string;
  readonly capture_providers: readonly {
    readonly name: "entire";
    readonly external_session_id?: string;
  }[];
  readonly work: {
    readonly work_item_id: string;
    readonly title: string;
    readonly objective: string;
    readonly constraints: readonly string[];
  };
  readonly parents: readonly [];
  readonly event_refs: readonly {
    readonly event_id: string;
    readonly path: string;
    readonly digest: Digest;
  }[];
  readonly git_state: { readonly path: string; readonly digest: Digest };
  readonly artifacts: readonly {
    readonly path: string;
    readonly digest: Digest;
    readonly media_type: string;
    readonly role: "git-patch" | "git-untracked-file";
    readonly byte_length: number;
  }[];
  readonly claims: readonly [];
  readonly evidence: readonly [];
  readonly open_questions: readonly string[];
  readonly exclusions: readonly HandoffExclusion[];
  readonly next_action: {
    readonly statement: string;
    readonly source_paths: readonly [string];
  };
  readonly extensions: {
    readonly "openworkcommons.org/source_checkpoint": {
      readonly provider: "entire";
      readonly provider_version: string;
      readonly external_checkpoint_id: string;
    };
    readonly "openworkcommons.org/provider_projection": {
      readonly path: string;
      readonly digest: Digest;
    };
    readonly "openworkcommons.org/provider_import_gaps": readonly string[];
    readonly "openworkcommons.org/event_boundary": "operator-authored-events-only";
  };
}

export interface HandoffExclusion {
  readonly category: string;
  readonly reason: string;
  readonly policy: "owc-v0-default-deny";
}

export interface HandoffArtifactReview {
  readonly path: string;
  readonly mediaType: string;
  readonly digest: Digest;
  readonly byteLength: number;
  readonly role: "git-patch" | "git-untracked-file";
}

export interface HandoffArchiveEntryReview {
  readonly path: string;
  readonly mediaType: string;
  readonly role:
    "event" | "git-state" | "checkpoint" | "artifact" | "extension";
  readonly digest: Digest;
  readonly byteLength: number;
  readonly requiredForVerification: true;
}

export interface HandoffInspection {
  readonly format: "open-work-commons-handoff-inspection";
  readonly schemaVersion: "0.1";
  readonly approvalDigest: Digest;
  readonly handoffBasisDigest: Digest;
  readonly capturedAt: string;
  readonly identifiers: {
    readonly archiveId: string;
    readonly checkpointId: string;
    readonly sessionId: string;
    readonly eventIds: readonly string[];
  };
  readonly signer: {
    readonly keyId: string;
    readonly fingerprint: Digest;
    readonly publicKey: string;
  };
  readonly included: {
    readonly operatorPlan: NormalizedOperatorHandoffPlan;
    readonly providerProjection: SafeEntireCheckpointProjection;
    readonly events: readonly NormalizedHandoffEvent[];
    readonly checkpoint: HandoffCheckpoint;
    readonly gitState: GitStateV0;
    readonly gitStateDigest: Digest;
    readonly artifacts: readonly HandoffArtifactReview[];
  };
  readonly excluded: readonly HandoffExclusion[];
  readonly gaps: {
    readonly imported: readonly string[];
    readonly resolvedByExactApproval: readonly string[];
    readonly residual: readonly string[];
    readonly blocking: readonly [];
  };
  readonly proposedArchive: {
    readonly rootCheckpoint: {
      readonly checkpointId: string;
      readonly path: string;
      readonly digest: Digest;
    };
    readonly entries: readonly HandoffArchiveEntryReview[];
    readonly payloadDigest: Digest;
    readonly limits: {
      readonly entryCount: number;
      readonly expandedBytes: number;
      readonly maxEntryBytes: number;
    };
  };
}

export interface ApprovedStoreBlob {
  readonly archivePath: string;
  readonly mediaType: string;
  readonly digest: Digest;
  readonly byteLength: number;
  readonly bytes: Uint8Array;
}

export interface ApprovedStoreEvent {
  readonly eventId: string;
  readonly eventDigest: Digest;
  readonly event: NormalizedHandoffEvent;
}

/** Exact immutable byte/event allowlist for one approved handoff. */
export interface HandoffStoreWritePlan {
  readonly format: "open-work-commons-exact-store-write-plan";
  readonly schemaVersion: "0.1";
  readonly approvalDigest: Digest;
  readonly archiveId: string;
  readonly blobs: readonly ApprovedStoreBlob[];
  readonly events: readonly ApprovedStoreEvent[];
}

export interface ApprovedHandoff {
  readonly inspection: HandoffInspection;
  readonly archive: LogicalArchive;
  readonly verification: ArchiveVerificationResult;
  readonly checkpoint: HandoffCheckpoint;
  readonly events: readonly NormalizedHandoffEvent[];
  readonly storeWritePlan: HandoffStoreWritePlan;
}

export interface HandoffStoreWriter {
  putBlob(input: {
    readonly bytes: Uint8Array;
    readonly mediaType?: string;
  }): Promise<BlobWriteResult>;
  appendEvent(input: unknown): Promise<EventAppendResult>;
}

export interface HandoffStorePersistenceResult {
  readonly blobs: readonly BlobWriteResult[];
  readonly events: readonly EventAppendResult[];
}

export type ExactHandoffStorePolicy = StorePolicy;

export type HandoffErrorCode =
  | "invalid_input"
  | "invalid_plan"
  | "entire_import_invalid"
  | "provider_mismatch"
  | "external_checkpoint_mismatch"
  | "blocking_import_gap"
  | "git_state_invalid"
  | "signing_identity_invalid"
  | "approval_mismatch"
  | "archive_construction_failed"
  | "store_plan_invalid";

export class HandoffError extends Error {
  constructor(
    readonly code: HandoffErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "HandoffError";
  }
}
