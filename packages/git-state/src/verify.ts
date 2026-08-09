import { captureGitState } from "./capture.js";
import {
  GitStateCaptureError,
  type CapturedGitState,
  type ExternalGitStateUnavailableReason,
  type ExternalGitStateVerification,
  type ExternalGitStateVerificationOptions,
  type GitArchiveArtifactReferenceV0,
  type GitStateArtifact,
  type GitStateV0,
  type GitUntrackedEntryV0,
} from "./types.js";

/**
 * Re-observe one local repository using the immutable choices declared by a
 * validated Git-state object. This function never fetches, writes, or invokes
 * a repository hook or content filter.
 */
export async function verifyExternalGitState(
  options: ExternalGitStateVerificationOptions,
): Promise<ExternalGitStateVerification> {
  if (!isSupportedDeclaredState(options?.declaredState)) {
    return unavailable("declared_state_unsupported");
  }

  const includePolicy = declaredIncludePolicy(options.declaredState);
  if (includePolicy === null) {
    return unavailable("declared_state_unsupported");
  }

  let observed: CapturedGitState;
  try {
    observed = await captureGitState({
      cwd: options.cwd,
      capturedAt: options.declaredState.captured_at,
      runner: options.runner,
      baseRevision: options.declaredState.base_commit,
      repositoryId: options.declaredState.repository_id,
      untrackedPolicy: includePolicy,
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    });
  } catch (error) {
    return unavailable(mapCaptureFailure(error));
  }

  if (!trackedPatchMatches(options.declaredState, observed)) {
    return {
      status: "mismatched",
      reason: "tracked_patch_mismatch",
    };
  }
  if (!untrackedManifestMatches(options.declaredState, observed)) {
    return {
      status: "mismatched",
      reason: "untracked_manifest_mismatch",
    };
  }
  if (!statesMatch(options.declaredState, observed.state)) {
    return { status: "mismatched", reason: "git_state_mismatch" };
  }
  return { status: "matched", reason: "exact_git_state_match" };
}

function declaredIncludePolicy(
  state: GitStateV0,
): "manifest-only" | "include" | null {
  const included = new Set(
    state.worktree.untracked.map((entry) => entry.included),
  );
  if (included.size > 1) return null;
  return included.has(true) ? "include" : "manifest-only";
}

function trackedPatchMatches(
  declared: GitStateV0,
  observed: CapturedGitState,
): boolean {
  const expected = declared.worktree.patch;
  const actualReference = observed.state.worktree.patch;
  const actualArtifact = observed.patchArtifact;
  if (expected === undefined) {
    return actualReference === undefined && actualArtifact === null;
  }
  if (actualReference === undefined || actualArtifact === null) return false;
  return (
    referencesEqual(expected, actualReference) &&
    artifactMatchesReference(actualArtifact, expected)
  );
}

function untrackedManifestMatches(
  declared: GitStateV0,
  observed: CapturedGitState,
): boolean {
  const actual = observed.state.worktree.untracked;
  if (declared.worktree.untracked.length !== actual.length) return false;
  for (let index = 0; index < declared.worktree.untracked.length; index++) {
    const expected = declared.worktree.untracked[index];
    const candidate = actual[index];
    if (
      !expected ||
      !candidate ||
      !untrackedEntriesEqual(expected, candidate)
    ) {
      return false;
    }
  }

  const expectedArtifacts = declared.worktree.untracked.flatMap((entry) =>
    entry.included ? [entry.artifact] : [],
  );
  if (expectedArtifacts.length !== observed.untrackedArtifacts.length) {
    return false;
  }
  return expectedArtifacts.every((reference, index) => {
    const artifact = observed.untrackedArtifacts[index];
    return (
      artifact !== undefined && artifactMatchesReference(artifact, reference)
    );
  });
}

function statesMatch(declared: GitStateV0, observed: GitStateV0): boolean {
  return Buffer.from(serializeState(declared)).equals(
    Buffer.from(serializeState(observed)),
  );
}

/** Produce the capture implementation's exact, compact v0 serialization. */
function serializeState(state: GitStateV0): Uint8Array {
  const worktree =
    state.worktree.patch === undefined
      ? {
          clean: state.worktree.clean,
          untracked: state.worktree.untracked.map(projectUntrackedEntry),
        }
      : {
          clean: state.worktree.clean,
          patch: projectReference(state.worktree.patch),
          untracked: state.worktree.untracked.map(projectUntrackedEntry),
        };
  return Buffer.from(
    JSON.stringify({
      schema_version: state.schema_version,
      repository_id: state.repository_id,
      object_format: state.object_format,
      captured_at: state.captured_at,
      base_commit: state.base_commit,
      head_commit: state.head_commit,
      head_tree: state.head_tree,
      head_ref: state.head_ref,
      worktree,
    }),
    "utf8",
  );
}

function projectUntrackedEntry(entry: GitUntrackedEntryV0): object {
  const commitment = {
    path: entry.path,
    digest: entry.digest,
    byte_length: entry.byte_length,
  };
  return entry.included
    ? {
        ...commitment,
        included: true,
        artifact: projectReference(entry.artifact),
      }
    : { ...commitment, included: false };
}

function projectReference(reference: GitArchiveArtifactReferenceV0): object {
  return {
    path: reference.path,
    digest: reference.digest,
    byte_length: reference.byte_length,
  };
}

function referencesEqual(
  left: GitArchiveArtifactReferenceV0,
  right: GitArchiveArtifactReferenceV0,
): boolean {
  return (
    left.path === right.path &&
    left.digest === right.digest &&
    left.byte_length === right.byte_length
  );
}

function artifactMatchesReference(
  artifact: GitStateArtifact,
  reference: GitArchiveArtifactReferenceV0,
): boolean {
  return (
    artifact.path === reference.path &&
    artifact.digest === reference.digest &&
    artifact.byteLength === reference.byte_length
  );
}

function untrackedEntriesEqual(
  left: GitUntrackedEntryV0,
  right: GitUntrackedEntryV0,
): boolean {
  return (
    JSON.stringify(projectUntrackedEntry(left)) ===
    JSON.stringify(projectUntrackedEntry(right))
  );
}

function mapCaptureFailure(error: unknown): ExternalGitStateUnavailableReason {
  if (!(error instanceof GitStateCaptureError)) return "git_unavailable";
  switch (error.code) {
    case "NOT_A_GIT_WORKTREE":
    case "INVALID_INPUT":
      return "repository_unavailable";
    case "SUBPROCESS_ERROR":
      return "git_unavailable";
    case "OUTPUT_LIMIT_EXCEEDED":
      return "verification_limit_exceeded";
    case "REPOSITORY_CHANGED_DURING_CAPTURE":
      return "repository_changed";
    case "UNRESOLVED_REVISION":
    case "BASE_NOT_ANCESTOR":
      return "declared_base_unavailable";
    case "AMBIGUOUS_GIT_OUTPUT":
      return "git_output_ambiguous";
    case "UNSAFE_UNTRACKED_PATH":
    case "UNSUPPORTED_GIT_OBJECT_FORMAT":
    case "UNSUPPORTED_REPOSITORY_STATE":
      return "repository_state_unsupported";
    case "INVALID_CAPTURE_TIME":
      return "declared_state_unsupported";
  }
}

function unavailable(
  reason: ExternalGitStateUnavailableReason,
): ExternalGitStateVerification {
  return { status: "unavailable", reason };
}

function isSupportedDeclaredState(value: unknown): value is GitStateV0 {
  if (!isRecord(value)) return false;
  const allowedRoot = new Set([
    "schema_version",
    "repository_id",
    "object_format",
    "captured_at",
    "base_commit",
    "head_commit",
    "head_tree",
    "head_ref",
    "worktree",
  ]);
  if (Object.keys(value).some((key) => !allowedRoot.has(key))) return false;
  if (
    value.schema_version !== "0.1" ||
    typeof value.repository_id !== "string" ||
    value.repository_id.length < 1 ||
    value.repository_id.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(value.repository_id) ||
    (value.object_format !== "sha1" && value.object_format !== "sha256") ||
    typeof value.captured_at !== "string" ||
    typeof value.base_commit !== "string" ||
    typeof value.head_commit !== "string" ||
    typeof value.head_tree !== "string" ||
    (value.head_ref !== null && typeof value.head_ref !== "string") ||
    !isRecord(value.worktree)
  ) {
    return false;
  }
  const oid =
    value.object_format === "sha1" ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/;
  if (
    !oid.test(value.base_commit) ||
    !oid.test(value.head_commit) ||
    !oid.test(value.head_tree)
  ) {
    return false;
  }
  const worktreeKeys = new Set(["clean", "patch", "untracked"]);
  if (
    Object.keys(value.worktree).some((key) => !worktreeKeys.has(key)) ||
    typeof value.worktree.clean !== "boolean" ||
    !Array.isArray(value.worktree.untracked) ||
    ("patch" in value.worktree && !isReference(value.worktree.patch)) ||
    !value.worktree.untracked.every(isUntrackedEntry)
  ) {
    return false;
  }
  return true;
}

function isUntrackedEntry(value: unknown): value is GitUntrackedEntryV0 {
  if (!isRecord(value) || typeof value.included !== "boolean") return false;
  const keys = new Set([
    "path",
    "digest",
    "byte_length",
    "included",
    "artifact",
  ]);
  if (
    Object.keys(value).some((key) => !keys.has(key)) ||
    typeof value.path !== "string" ||
    !isDigest(value.digest) ||
    !isNonNegativeInteger(value.byte_length)
  ) {
    return false;
  }
  return value.included ? isReference(value.artifact) : !("artifact" in value);
}

function isReference(value: unknown): value is GitArchiveArtifactReferenceV0 {
  return (
    isRecord(value) &&
    Object.keys(value).every((key) =>
      ["path", "digest", "byte_length"].includes(key),
    ) &&
    typeof value.path === "string" &&
    isDigest(value.digest) &&
    isNonNegativeInteger(value.byte_length)
  );
}

function isDigest(value: unknown): value is `sha256:${string}` {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
