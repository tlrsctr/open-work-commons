import {
  DEFAULT_VERIFIER_LIMITS,
  parseJsonSafely,
  type ArchiveVerificationResult,
  type LogicalArchive,
} from "../../../packages/archive/src/index.js";
import type { GitStateV0 } from "../../../packages/git-state/src/index.js";

/**
 * Resolve the Git-state selected by the verified root checkpoint. This helper
 * is deliberately usable only after the in-memory archive has passed the
 * complete byte, signature, schema, and graph verifier.
 */
export function readVerifiedRootGitState(
  archive: LogicalArchive,
  verification: ArchiveVerificationResult,
): GitStateV0 | null {
  if (!verification.integrity.valid || !verification.signer.signatureValid) {
    return null;
  }
  try {
    const manifest = parseBounded(archive.manifestBytes);
    if (!isRecord(manifest) || !isRecord(manifest.root_checkpoint)) return null;
    const checkpointPath = manifest.root_checkpoint.path;
    if (typeof checkpointPath !== "string") return null;
    const checkpointEntry = archive.entries.find(
      (entry) => entry.path === checkpointPath && entry.kind !== "special",
    );
    if (!checkpointEntry) return null;
    const checkpoint = parseBounded(checkpointEntry.bytes);
    if (!isRecord(checkpoint) || !isRecord(checkpoint.git_state)) return null;
    const gitStatePath = checkpoint.git_state.path;
    if (typeof gitStatePath !== "string") return null;
    const gitStateEntry = archive.entries.find(
      (entry) => entry.path === gitStatePath && entry.kind !== "special",
    );
    if (!gitStateEntry) return null;
    const gitState = parseBounded(gitStateEntry.bytes);
    return isRecord(gitState) ? (gitState as unknown as GitStateV0) : null;
  } catch {
    return null;
  }
}

function parseBounded(bytes: Uint8Array): unknown {
  return parseJsonSafely(bytes, {
    maxDepth: DEFAULT_VERIFIER_LIMITS.maxJsonDepth,
    maxStringBytes: DEFAULT_VERIFIER_LIMITS.maxJsonStringBytes,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
