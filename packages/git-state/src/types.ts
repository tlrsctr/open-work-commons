export type GitObjectFormat = "sha1" | "sha256";

export type OwcDigest = `sha256:${string}`;

export interface GitCommandRequest {
  readonly args: readonly string[];
  readonly cwd: string;
  readonly maxStdoutBytes: number;
  readonly timeoutMs: number;
}

export interface GitCommandResult {
  readonly exitCode: number | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  readonly signal: NodeJS.Signals | null;
}

export interface GitCommandRunner {
  run(request: GitCommandRequest): Promise<GitCommandResult>;
}

export interface GitStateCaptureLimits {
  readonly commandTimeoutMs: number;
  readonly metadataOutputBytes: number;
  readonly statusOutputBytes: number;
  readonly patchSectionBytes: number;
  readonly patchArtifactBytes: number;
  readonly untrackedEntryCount: number;
  readonly untrackedFileBytes: number;
  readonly untrackedTotalBytes: number;
}

export interface GitStateCaptureOptions {
  readonly cwd: string;
  readonly capturedAt: string;
  readonly runner: GitCommandRunner;
  readonly baseRevision?: string;
  readonly repositoryId?: string;
  readonly untrackedPolicy?: "manifest-only" | "include";
  readonly limits?: Partial<GitStateCaptureLimits>;
}

export interface GitArchiveArtifactReferenceV0 {
  readonly path: string;
  readonly digest: OwcDigest;
  readonly byte_length: number;
}

export type GitPatchReferenceV0 = GitArchiveArtifactReferenceV0;

interface GitUntrackedCommitmentV0 {
  /** Repository-relative identity; never interpreted as an archive path. */
  readonly path: string;
  readonly digest: OwcDigest;
  readonly byte_length: number;
}

export type GitUntrackedEntryV0 =
  | (GitUntrackedCommitmentV0 & {
      readonly included: false;
      readonly artifact?: never;
    })
  | (GitUntrackedCommitmentV0 & {
      readonly included: true;
      readonly artifact: GitArchiveArtifactReferenceV0;
    });

export interface GitStateV0 {
  readonly schema_version: "0.1";
  readonly repository_id: string;
  readonly object_format: GitObjectFormat;
  readonly captured_at: string;
  readonly base_commit: string;
  readonly head_commit: string;
  readonly head_tree: string;
  readonly head_ref: string | null;
  readonly worktree: {
    readonly clean: boolean;
    readonly patch?: GitPatchReferenceV0;
    readonly untracked: readonly GitUntrackedEntryV0[];
  };
}

export interface GitStateArtifact {
  readonly path: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
  readonly digest: OwcDigest;
  readonly byteLength: number;
}

export interface CapturedGitState {
  readonly state: GitStateV0;
  readonly stateBytes: Uint8Array;
  readonly stateDigest: OwcDigest;
  readonly patchArtifact: GitStateArtifact | null;
  readonly untrackedArtifacts: readonly GitStateArtifact[];
}

export type ExternalGitStateMismatchReason =
  | "git_state_mismatch"
  | "tracked_patch_mismatch"
  | "untracked_manifest_mismatch";

export type ExternalGitStateUnavailableReason =
  | "declared_base_unavailable"
  | "declared_state_unsupported"
  | "git_output_ambiguous"
  | "git_unavailable"
  | "repository_changed"
  | "repository_state_unsupported"
  | "repository_unavailable"
  | "verification_limit_exceeded";

/**
 * A bounded, non-content-bearing comparison result. No local path, Git
 * diagnostic, patch byte, or untracked file byte is included.
 */
export type ExternalGitStateVerification =
  | {
      readonly status: "matched";
      readonly reason: "exact_git_state_match";
    }
  | {
      readonly status: "mismatched";
      readonly reason: ExternalGitStateMismatchReason;
    }
  | {
      readonly status: "unavailable";
      readonly reason: ExternalGitStateUnavailableReason;
    };

export interface ExternalGitStateVerificationOptions {
  readonly cwd: string;
  /** A Git-state object already validated against the OWC v0 contract. */
  readonly declaredState: GitStateV0;
  readonly runner: GitCommandRunner;
  readonly limits?: Partial<GitStateCaptureLimits>;
}

export type GitStateCaptureErrorCode =
  | "AMBIGUOUS_GIT_OUTPUT"
  | "BASE_NOT_ANCESTOR"
  | "INVALID_CAPTURE_TIME"
  | "INVALID_INPUT"
  | "NOT_A_GIT_WORKTREE"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "REPOSITORY_CHANGED_DURING_CAPTURE"
  | "SUBPROCESS_ERROR"
  | "UNRESOLVED_REVISION"
  | "UNSAFE_UNTRACKED_PATH"
  | "UNSUPPORTED_GIT_OBJECT_FORMAT"
  | "UNSUPPORTED_REPOSITORY_STATE";

export class GitStateCaptureError extends Error {
  readonly code: GitStateCaptureErrorCode;

  constructor(code: GitStateCaptureErrorCode, message: string) {
    super(message);
    this.name = "GitStateCaptureError";
    this.code = code;
  }
}
