import type { KeyObject } from "node:crypto";

import { canonicalJsonBytes } from "./canonical-json.js";
import {
  publicKeyBase64Url,
  publicKeyForPrivateKey,
  sha256,
  signEd25519,
  signerFingerprint,
  verifyEd25519,
} from "./crypto.js";
import { isSafeArchivePath } from "./path.js";
import { parseJsonSafely, SafeJsonError } from "./safe-json.js";
import type {
  ArchiveEntryDescriptor,
  ArchiveManifest,
  ArchiveVerificationResult,
  CreateSignedArchiveInput,
  Digest,
  LogicalArchive,
  LogicalArchiveEntry,
  VerificationIssue,
  VerificationIssueCode,
  VerifierLimits,
  VerifyArchiveOptions,
} from "./types.js";
import { ArchiveInputError } from "./types.js";
import {
  validateCheckpoint,
  validateEvidenceObject,
  validateEvent,
  validateGitState,
  validateManifest,
  type PathDigestReference,
  type ValidatedCheckpoint,
  type ValidatedEvidence,
  type ValidatedEvent,
  type ValidatedGitState,
} from "./validation.js";

export const DEFAULT_VERIFIER_LIMITS: Readonly<VerifierLimits> = Object.freeze({
  maxManifestBytes: 1024 * 1024,
  maxEntryCount: 4096,
  maxExpandedBytes: 256 * 1024 * 1024,
  maxEntryBytes: 64 * 1024 * 1024,
  maxJsonDepth: 64,
  maxJsonStringBytes: 1024 * 1024,
});

const GIT_PATCH_MEDIA_TYPE = "application/vnd.openworkcommons.git-patch-v1";
const UNTRACKED_FILE_MEDIA_TYPE = "application/octet-stream";

export function createSignedArchive(
  input: CreateSignedArchiveInput,
): LogicalArchive {
  assertSigningKey(input.signingKey.privateKey);

  const entries: LogicalArchiveEntry[] = input.entries
    .map((entry): LogicalArchiveEntry => {
      const bytes =
        "json" in entry
          ? canonicalJsonBytes(entry.json, {
              maxDepth: DEFAULT_VERIFIER_LIMITS.maxJsonDepth,
              maxStringBytes: DEFAULT_VERIFIER_LIMITS.maxJsonStringBytes,
            })
          : cloneBytes(entry.bytes);
      return { path: entry.path, bytes, kind: "file" };
    })
    .sort((left, right) => compareStrings(left.path, right.path));

  const inputByPath = new Map(
    input.entries.map((entry) => [entry.path, entry]),
  );
  const descriptors: ArchiveEntryDescriptor[] = entries.map((entry) => {
    const metadata = inputByPath.get(entry.path);
    if (!metadata) {
      throw new ArchiveInputError(
        "duplicate_path",
        "Archive construction received duplicate entry paths.",
      );
    }
    return {
      path: entry.path,
      media_type: metadata.mediaType,
      role: metadata.role,
      byte_length: entry.bytes.byteLength,
      digest: sha256(entry.bytes),
      required_for_verification: metadata.requiredForVerification ?? true,
    };
  });

  if (
    new Set(input.entries.map((entry) => entry.path)).size !==
    input.entries.length
  ) {
    throw new ArchiveInputError(
      "duplicate_path",
      "Archive construction received duplicate entry paths.",
    );
  }

  const rootDescriptor = descriptors.find(
    (entry) => entry.path === input.rootCheckpoint.path,
  );
  if (!rootDescriptor || rootDescriptor.role !== "checkpoint") {
    throw new ArchiveInputError(
      "reference_missing",
      "The root checkpoint must identify a checkpoint entry.",
    );
  }

  const expandedBytes = entries.reduce(
    (total, entry) => total + entry.bytes.byteLength,
    0,
  );
  const maximumEntryBytes = entries.reduce(
    (maximum, entry) => Math.max(maximum, entry.bytes.byteLength),
    0,
  );
  const declaredLimits = input.limits ?? {
    entry_count: entries.length,
    expanded_bytes: expandedBytes,
    max_entry_bytes: maximumEntryBytes,
  };
  const publicKey = publicKeyForPrivateKey(input.signingKey.privateKey);
  const rawPublicKey = publicKeyBase64Url(publicKey);

  const unsignedManifest = {
    format: "open-work-commons-portable-archive",
    schema_version: "0.1",
    archive_id: input.archiveId,
    created_at: input.createdAt,
    root_checkpoint: {
      checkpoint_id: input.rootCheckpoint.checkpointId,
      path: input.rootCheckpoint.path,
      digest: rootDescriptor.digest,
    },
    entries: descriptors,
    exclusions: input.exclusions.map((exclusion) => ({ ...exclusion })),
    limits: { ...declaredLimits },
    signature: {
      canonicalization: "RFC8785",
      digest_algorithm: "sha256",
      signature_algorithm: "ed25519",
      key_id: input.signingKey.keyId,
      public_key: rawPublicKey,
      payload_digest: "" as Digest,
      value: "",
    },
    ...(input.extensions === undefined ? {} : { extensions: input.extensions }),
  } as const;
  const signingPayload = canonicalJsonBytes(
    signingProjection(unsignedManifest),
  );
  const manifest: ArchiveManifest = {
    ...unsignedManifest,
    signature: {
      ...unsignedManifest.signature,
      payload_digest: sha256(signingPayload),
      value: signEd25519(signingPayload, input.signingKey.privateKey),
    },
  };
  const archive: LogicalArchive = {
    manifestBytes: canonicalJsonBytes(manifest),
    entries: entries.map((entry) => ({
      path: entry.path,
      bytes: cloneBytes(entry.bytes),
      kind: "file",
    })),
  };

  const verification = verifyLogicalArchive(archive, {
    trustedSignerFingerprints: [signerFingerprint(rawPublicKey)],
  });
  if (!verification.integrity.valid) {
    const first = verification.integrity.issues[0];
    throw new ArchiveInputError(
      first?.code ?? "invalid_archive",
      first?.message ?? "Archive construction failed v0 verification.",
    );
  }
  return archive;
}

export function verifyLogicalArchive(
  archive: LogicalArchive,
  options: VerifyArchiveOptions = {},
): ArchiveVerificationResult {
  const limits = resolveVerifierLimits(options.limits);
  const issues: VerificationIssue[] = [];
  let manifest: ArchiveManifest | null = null;
  let signerKeyId: string | null = null;
  let fingerprint: Digest | null = null;
  let signatureValid = false;

  if (
    !archive ||
    !(archive.manifestBytes instanceof Uint8Array) ||
    !Array.isArray(archive.entries)
  ) {
    addIssue(
      issues,
      "invalid_archive",
      "$",
      "Logical archive representation is invalid.",
    );
    return result(null, issues, null, null, false, options);
  }
  if (archive.manifestBytes.byteLength > limits.maxManifestBytes) {
    addIssue(
      issues,
      "manifest_too_large",
      "archive-manifest.json",
      "Manifest exceeds the configured byte limit.",
    );
    return result(null, issues, null, null, false, options);
  }

  let parsedManifest: unknown;
  try {
    parsedManifest = parseJsonSafely(archive.manifestBytes, {
      maxDepth: limits.maxJsonDepth,
      maxStringBytes: limits.maxJsonStringBytes,
    });
  } catch (error) {
    const duplicate =
      error instanceof SafeJsonError && error.kind === "duplicate-key";
    addIssue(
      issues,
      duplicate ? "manifest_duplicate_json_key" : "manifest_json_invalid",
      "archive-manifest.json",
      duplicate
        ? "Manifest contains a duplicate JSON object key."
        : "Manifest is not valid bounded UTF-8 JSON.",
    );
    return result(null, issues, null, null, false, options);
  }

  const checkedManifest = validateManifest(parsedManifest);
  if (checkedManifest.unsupportedVersion) {
    addIssue(
      issues,
      "unsupported_archive_version",
      "$.schema_version",
      "Archive version is not supported by this verifier.",
    );
  }
  for (const problem of checkedManifest.problems) {
    const pathProblem = /(?:^|\.)path$/.test(problem.location);
    addIssue(
      issues,
      pathProblem ? "unsafe_path" : "manifest_schema_invalid",
      problem.location,
      pathProblem ? "Manifest entry path is unsafe." : problem.message,
    );
  }
  if (!checkedManifest.value) {
    return result(null, issues, null, null, false, options);
  }
  manifest = checkedManifest.value;
  signerKeyId = manifest.signature.key_id;
  try {
    fingerprint = signerFingerprint(manifest.signature.public_key);
  } catch {
    addIssue(
      issues,
      "manifest_schema_invalid",
      "$.signature.public_key",
      "Embedded signer public key is invalid.",
    );
  }

  validatePathsAndLimits(archive, manifest, limits, issues);
  if (issues.length === 0) {
    validateEntryBytes(archive, manifest, issues);
  }

  let signingPayload: Uint8Array | null = null;
  try {
    signingPayload = canonicalJsonBytes(signingProjection(manifest), {
      maxDepth: limits.maxJsonDepth,
      maxStringBytes: limits.maxJsonStringBytes,
    });
    if (sha256(signingPayload) !== manifest.signature.payload_digest) {
      addIssue(
        issues,
        "payload_digest_mismatch",
        "$.signature.payload_digest",
        "Manifest signing-payload digest does not match.",
      );
    }
    signatureValid = verifyEd25519(
      signingPayload,
      manifest.signature.value,
      manifest.signature.public_key,
    );
    if (!signatureValid) {
      addIssue(
        issues,
        "signature_invalid",
        "$.signature.value",
        "Manifest Ed25519 signature is invalid.",
      );
    }
  } catch {
    addIssue(
      issues,
      "signature_invalid",
      "$.signature",
      "Manifest signing projection could not be verified.",
    );
  }

  // Captured JSON remains opaque until every byte-level and signature check has
  // succeeded. It is parsed as data only; no entry is rendered or executed.
  if (issues.length === 0 && signingPayload) {
    validateNormativeEntriesAndGraph(archive, manifest, limits, issues);
  }

  return result(
    manifest,
    issues,
    signerKeyId,
    fingerprint,
    signatureValid,
    options,
  );
}

export function signingProjection(manifest: ArchiveManifest | object): object {
  const source = manifest as ArchiveManifest;
  return {
    ...source,
    signature: {
      canonicalization: source.signature.canonicalization,
      digest_algorithm: source.signature.digest_algorithm,
      signature_algorithm: source.signature.signature_algorithm,
      key_id: source.signature.key_id,
      public_key: source.signature.public_key,
    },
  };
}

function validatePathsAndLimits(
  archive: LogicalArchive,
  manifest: ArchiveManifest,
  limits: VerifierLimits,
  issues: VerificationIssue[],
): void {
  if (
    manifest.entries.length > limits.maxEntryCount ||
    manifest.limits.entry_count > limits.maxEntryCount
  ) {
    addIssue(
      issues,
      "entry_count_limit",
      "$.limits.entry_count",
      "Archive exceeds the configured entry-count limit.",
    );
  }
  if (manifest.limits.expanded_bytes > limits.maxExpandedBytes) {
    addIssue(
      issues,
      "expanded_bytes_limit",
      "$.limits.expanded_bytes",
      "Archive exceeds the configured expanded-byte limit.",
    );
  }
  if (manifest.limits.max_entry_bytes > limits.maxEntryBytes) {
    addIssue(
      issues,
      "entry_bytes_limit",
      "$.limits.max_entry_bytes",
      "Archive exceeds the configured per-entry byte limit.",
    );
  }

  const manifestPaths = new Set<string>();
  manifest.entries.forEach((entry, index) => {
    if (!isSafeArchivePath(entry.path)) {
      addIssue(
        issues,
        "unsafe_path",
        `$.entries[${index}].path`,
        "Manifest entry path is unsafe.",
      );
      return;
    }
    if (manifestPaths.has(entry.path)) {
      addIssue(
        issues,
        "duplicate_path",
        `$.entries[${index}].path`,
        "Manifest contains a duplicate archive path.",
      );
    }
    manifestPaths.add(entry.path);
  });

  const logicalPaths = new Set<string>();
  let expandedBytes = 0;
  let maximumEntryBytes = 0;
  archive.entries.forEach((entry, index) => {
    const location = `logical.entries[${index}]`;
    if (!entry || typeof entry !== "object") {
      addIssue(
        issues,
        "invalid_archive",
        location,
        "Logical archive entry is invalid.",
      );
      return;
    }
    if (!isSafeArchivePath(entry.path)) {
      addIssue(
        issues,
        "unsafe_path",
        `${location}.path`,
        "Logical archive entry path is unsafe.",
      );
      return;
    }
    if (logicalPaths.has(entry.path)) {
      addIssue(
        issues,
        "duplicate_path",
        `${location}.path`,
        "Logical archive contains a duplicate archive path.",
      );
    }
    logicalPaths.add(entry.path);
    if ((entry.kind ?? "file") !== "file") {
      addIssue(
        issues,
        "special_entry",
        location,
        "Logical archive contains a non-file entry.",
      );
      return;
    }
    if (!(entry.bytes instanceof Uint8Array)) {
      addIssue(
        issues,
        "invalid_archive",
        `${location}.bytes`,
        "Logical archive entry bytes are invalid.",
      );
      return;
    }
    expandedBytes += entry.bytes.byteLength;
    maximumEntryBytes = Math.max(maximumEntryBytes, entry.bytes.byteLength);
    if (entry.bytes.byteLength > limits.maxEntryBytes) {
      addIssue(
        issues,
        "entry_bytes_limit",
        entry.path,
        "Archive entry exceeds the configured byte limit.",
      );
    }
  });

  if (archive.entries.length > limits.maxEntryCount) {
    addIssue(
      issues,
      "entry_count_limit",
      "logical.entries",
      "Logical archive exceeds the configured entry-count limit.",
    );
  }
  if (expandedBytes > limits.maxExpandedBytes) {
    addIssue(
      issues,
      "expanded_bytes_limit",
      "logical.entries",
      "Logical archive exceeds the configured expanded-byte limit.",
    );
  }
  if (
    manifest.entries.length > manifest.limits.entry_count ||
    expandedBytes > manifest.limits.expanded_bytes ||
    maximumEntryBytes > manifest.limits.max_entry_bytes
  ) {
    addIssue(
      issues,
      "declared_limit_invalid",
      "$.limits",
      "Archive content exceeds its signed declared limits.",
    );
  }

  for (const path of manifestPaths) {
    if (!logicalPaths.has(path)) {
      addIssue(
        issues,
        "missing_entry",
        path,
        "A manifest-listed entry is missing.",
      );
    }
  }
  for (const path of logicalPaths) {
    if (!manifestPaths.has(path)) {
      addIssue(
        issues,
        "unlisted_entry",
        path,
        "Logical archive contains an unlisted entry.",
      );
    }
  }
}

function validateEntryBytes(
  archive: LogicalArchive,
  manifest: ArchiveManifest,
  issues: VerificationIssue[],
): void {
  const logicalByPath = uniqueLogicalEntryMap(archive.entries);
  for (const descriptor of manifest.entries) {
    if (!isSafeArchivePath(descriptor.path)) continue;
    const entry = logicalByPath.get(descriptor.path);
    if (!entry || !(entry.bytes instanceof Uint8Array)) continue;
    if (entry.bytes.byteLength !== descriptor.byte_length) {
      addIssue(
        issues,
        "entry_length_mismatch",
        descriptor.path,
        "Archive entry byte length does not match the manifest.",
      );
    }
    if (sha256(entry.bytes) !== descriptor.digest) {
      addIssue(
        issues,
        "entry_digest_mismatch",
        descriptor.path,
        "Archive entry digest does not match the manifest.",
      );
    }
  }
}

function validateNormativeEntriesAndGraph(
  archive: LogicalArchive,
  manifest: ArchiveManifest,
  limits: VerifierLimits,
  issues: VerificationIssue[],
): void {
  const bytesByPath = uniqueLogicalEntryMap(archive.entries);
  const descriptorByPath = new Map(
    manifest.entries.map((entry) => [entry.path, entry]),
  );
  const events = new Map<string, ValidatedEvent>();
  const evidenceObjects = new Map<string, ValidatedEvidence>();
  const gitStates = new Map<string, ValidatedGitState>();
  const checkpoints = new Map<string, ValidatedCheckpoint>();

  for (const descriptor of manifest.entries) {
    if (
      descriptor.role !== "event" &&
      descriptor.role !== "git-state" &&
      descriptor.role !== "checkpoint" &&
      descriptor.role !== "evidence"
    ) {
      continue;
    }
    if (descriptor.media_type !== "application/json") {
      addIssue(
        issues,
        "entry_schema_invalid",
        descriptor.path,
        "Normative JSON entry has the wrong media type.",
      );
      continue;
    }
    const entry = bytesByPath.get(descriptor.path);
    if (!entry) continue;
    let parsed: unknown;
    try {
      parsed = parseJsonSafely(entry.bytes, {
        maxDepth: limits.maxJsonDepth,
        maxStringBytes: limits.maxJsonStringBytes,
      });
    } catch {
      addIssue(
        issues,
        "entry_json_invalid",
        descriptor.path,
        "Normative entry is not valid bounded UTF-8 JSON.",
      );
      continue;
    }

    const checked =
      descriptor.role === "event"
        ? validateEvent(parsed, descriptor.path)
        : descriptor.role === "git-state"
          ? validateGitState(parsed, descriptor.path)
          : descriptor.role === "checkpoint"
            ? validateCheckpoint(parsed, descriptor.path)
            : validateEvidenceObject(parsed, descriptor.path);
    for (const problem of checked.problems) {
      addIssue(
        issues,
        "entry_schema_invalid",
        problem.location,
        problem.message,
      );
    }
    if (!checked.value) continue;
    if (descriptor.role === "event") {
      events.set(descriptor.path, checked.value as ValidatedEvent);
    } else if (descriptor.role === "git-state") {
      gitStates.set(descriptor.path, checked.value as ValidatedGitState);
    } else if (descriptor.role === "checkpoint") {
      checkpoints.set(descriptor.path, checked.value as ValidatedCheckpoint);
    } else {
      evidenceObjects.set(descriptor.path, checked.value as ValidatedEvidence);
    }
  }

  const rootDescriptor = descriptorByPath.get(manifest.root_checkpoint.path);
  const rootCheckpoint = checkpoints.get(manifest.root_checkpoint.path);
  if (
    !rootDescriptor ||
    rootDescriptor.role !== "checkpoint" ||
    !rootCheckpoint
  ) {
    referenceMissing(issues, "$.root_checkpoint");
  } else {
    if (
      rootDescriptor.digest !== manifest.root_checkpoint.digest ||
      rootCheckpoint.checkpointId !== manifest.root_checkpoint.checkpoint_id
    ) {
      addIssue(
        issues,
        "reference_identity_mismatch",
        "$.root_checkpoint",
        "Root checkpoint reference is inconsistent.",
      );
    }
  }

  for (const [path, event] of events) {
    if (event.payloadPath) {
      resolveReference(
        { path: event.payloadPath, digest: event.payloadDigest },
        descriptorByPath,
        issues,
        `${path}.payload`,
      );
    }
  }

  for (const [path, state] of gitStates) {
    if (state.patch) {
      const descriptor = resolveSizedReference(
        state.patch,
        descriptorByPath,
        issues,
        `${path}.worktree.patch`,
        "artifact",
      );
      if (descriptor && descriptor.media_type !== GIT_PATCH_MEDIA_TYPE) {
        addIssue(
          issues,
          "reference_identity_mismatch",
          `${path}.worktree.patch`,
          "Git patch artifact has the wrong media type.",
        );
      }
    }
    state.includedUntracked.forEach((entry, index) => {
      const descriptor = resolveSizedReference(
        entry.artifact,
        descriptorByPath,
        issues,
        `${path}.worktree.untracked[${index}]`,
        "artifact",
      );
      if (descriptor && descriptor.media_type !== UNTRACKED_FILE_MEDIA_TYPE) {
        addIssue(
          issues,
          "reference_identity_mismatch",
          `${path}.worktree.untracked[${index}].artifact`,
          "Included untracked artifact has the wrong media type.",
        );
      }
    });
  }

  for (const [path, checkpoint] of checkpoints) {
    const referencedEvents: ValidatedEvent[] = [];
    checkpoint.eventRefs.forEach((reference, index) => {
      const descriptor = resolveReference(
        reference,
        descriptorByPath,
        issues,
        `${path}.event_refs[${index}]`,
        "event",
      );
      const event = events.get(reference.path);
      if (descriptor && event) {
        if (
          event.eventId !== reference.eventId ||
          event.sessionId !== checkpoint.sessionId
        ) {
          addIssue(
            issues,
            "reference_identity_mismatch",
            `${path}.event_refs[${index}]`,
            "Checkpoint event reference identity is inconsistent.",
          );
        }
        referencedEvents.push(event);
      }
    });
    validateEventSequence(referencedEvents, path, issues);

    resolveReference(
      checkpoint.gitState,
      descriptorByPath,
      issues,
      `${path}.git_state`,
      "git-state",
    );
    if (!gitStates.has(checkpoint.gitState.path)) {
      referenceMissing(issues, `${path}.git_state`);
    }
    checkpoint.artifactRefs.forEach((reference, index) =>
      resolveSizedReference(
        reference,
        descriptorByPath,
        issues,
        `${path}.artifacts[${index}]`,
        "artifact",
      ),
    );
    checkpoint.evidence.forEach((checkpointEvidence, index) => {
      if (!checkpointEvidence.source) return;
      const location = `${path}.evidence[${index}].source`;
      const descriptor = resolveReference(
        checkpointEvidence.source,
        descriptorByPath,
        issues,
        location,
        "evidence",
      );
      const evidenceObject = evidenceObjects.get(
        checkpointEvidence.source.path,
      );
      if (!descriptor || !evidenceObject) {
        if (descriptor && !evidenceObject) referenceMissing(issues, location);
        return;
      }
      if (!sameEvidenceIdentity(checkpointEvidence, evidenceObject)) {
        addIssue(
          issues,
          "reference_identity_mismatch",
          location,
          "Checkpoint evidence identity is inconsistent with its source object.",
        );
      }
    });
    checkpoint.nextActionSourcePaths.forEach((sourcePath, index) => {
      if (!descriptorByPath.has(sourcePath)) {
        referenceMissing(issues, `${path}.next_action.source_paths[${index}]`);
      }
    });
    checkpoint.parents.forEach((reference, index) => {
      const descriptor = resolveReference(
        reference,
        descriptorByPath,
        issues,
        `${path}.parents[${index}]`,
        "checkpoint",
      );
      const parent = checkpoints.get(reference.path);
      if (
        descriptor &&
        parent &&
        parent.checkpointId !== reference.checkpointId
      ) {
        addIssue(
          issues,
          "reference_identity_mismatch",
          `${path}.parents[${index}]`,
          "Checkpoint parent identity is inconsistent.",
        );
      }
      if (!parent) referenceMissing(issues, `${path}.parents[${index}]`);
    });
  }

  validateCheckpointAcyclic(checkpoints, issues);
}

function sameEvidenceIdentity(
  left: ValidatedEvidence,
  right: ValidatedEvidence,
): boolean {
  return (
    left.evidenceId === right.evidenceId &&
    left.kind === right.kind &&
    left.issuer === right.issuer &&
    left.subjectDigest === right.subjectDigest &&
    left.result === right.result &&
    left.observedAt === right.observedAt
  );
}

function validateEventSequence(
  events: readonly ValidatedEvent[],
  checkpointPath: string,
  issues: VerificationIssue[],
): void {
  events.forEach((event, index) => {
    const previous = events[index - 1];
    if (
      event.sequence !== index ||
      (index === 0
        ? event.previousEventId !== null
        : event.previousEventId !== previous?.eventId)
    ) {
      addIssue(
        issues,
        "reference_identity_mismatch",
        `${checkpointPath}.event_refs[${index}]`,
        "Checkpoint event sequence is not a contiguous session prefix.",
      );
    }
  });
}

function validateCheckpointAcyclic(
  checkpoints: ReadonlyMap<string, ValidatedCheckpoint>,
  issues: VerificationIssue[],
): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (path: string): boolean => {
    if (visiting.has(path)) return false;
    if (visited.has(path)) return true;
    visiting.add(path);
    const checkpoint = checkpoints.get(path);
    if (checkpoint) {
      for (const parent of checkpoint.parents) {
        if (!visit(parent.path)) return false;
      }
    }
    visiting.delete(path);
    visited.add(path);
    return true;
  };
  for (const path of checkpoints.keys()) {
    if (!visit(path)) {
      addIssue(
        issues,
        "checkpoint_cycle",
        path,
        "Checkpoint parent graph contains a cycle.",
      );
      return;
    }
  }
}

function resolveReference(
  reference: PathDigestReference,
  descriptors: ReadonlyMap<string, ArchiveEntryDescriptor>,
  issues: VerificationIssue[],
  location: string,
  requiredRole?: ArchiveEntryDescriptor["role"],
): ArchiveEntryDescriptor | null {
  const descriptor = descriptors.get(reference.path);
  if (
    !descriptor ||
    (requiredRole !== undefined && descriptor.role !== requiredRole)
  ) {
    referenceMissing(issues, location);
    return null;
  }
  if (descriptor.digest !== reference.digest) {
    addIssue(
      issues,
      "reference_digest_mismatch",
      location,
      "Object reference digest is inconsistent with the manifest.",
    );
  }
  return descriptor;
}

function resolveSizedReference(
  reference: PathDigestReference & { readonly byteLength: number },
  descriptors: ReadonlyMap<string, ArchiveEntryDescriptor>,
  issues: VerificationIssue[],
  location: string,
  requiredRole?: ArchiveEntryDescriptor["role"],
): ArchiveEntryDescriptor | null {
  const descriptor = resolveReference(
    reference,
    descriptors,
    issues,
    location,
    requiredRole,
  );
  if (descriptor && descriptor.byte_length !== reference.byteLength) {
    addIssue(
      issues,
      "reference_identity_mismatch",
      location,
      "Object reference byte length is inconsistent with the manifest.",
    );
  }
  return descriptor;
}

function referenceMissing(issues: VerificationIssue[], location: string): void {
  addIssue(
    issues,
    "reference_missing",
    location,
    "Required archive object reference cannot be resolved.",
  );
}

function uniqueLogicalEntryMap(
  entries: readonly LogicalArchiveEntry[],
): Map<string, LogicalArchiveEntry> {
  const output = new Map<string, LogicalArchiveEntry>();
  for (const entry of entries) {
    if (
      entry &&
      typeof entry === "object" &&
      isSafeArchivePath(entry.path) &&
      !output.has(entry.path)
    ) {
      output.set(entry.path, entry);
    }
  }
  return output;
}

function result(
  manifest: ArchiveManifest | null,
  issues: readonly VerificationIssue[],
  keyId: string | null,
  fingerprint: Digest | null,
  signatureValid: boolean,
  options: VerifyArchiveOptions,
): ArchiveVerificationResult {
  const anchors = options.trustedSignerFingerprints;
  const trust =
    fingerprint === null
      ? "unavailable"
      : anchors === undefined || anchors.length === 0
        ? "not-configured"
        : anchors.includes(fingerprint)
          ? "trusted"
          : "untrusted";
  return {
    integrity: { valid: issues.length === 0, issues },
    signer: {
      keyId,
      fingerprint,
      signatureValid,
      trust,
      trusted: trust === "trusted",
    },
    archive: {
      archiveId: manifest?.archive_id ?? null,
      rootCheckpointId: manifest?.root_checkpoint.checkpoint_id ?? null,
      payloadDigest: manifest?.signature.payload_digest ?? null,
      entryCount: manifest?.entries.length ?? null,
    },
    externalRepositoryVerification: { status: "not-checked" },
  };
}

function resolveVerifierLimits(
  overrides: Partial<VerifierLimits> | undefined,
): VerifierLimits {
  const limits = { ...DEFAULT_VERIFIER_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`${name} must be a positive safe integer.`);
    }
  }
  return limits;
}

function assertSigningKey(privateKey: KeyObject): void {
  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError("Archive signing requires an Ed25519 private key.");
  }
}

function cloneBytes(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("Archive entry bytes must be a Uint8Array.");
  }
  return Uint8Array.from(bytes);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function addIssue(
  issues: VerificationIssue[],
  code: VerificationIssueCode,
  location: string,
  message: string,
): void {
  if (
    !issues.some((issue) => issue.code === code && issue.location === location)
  ) {
    issues.push({ code, location, message });
  }
}
