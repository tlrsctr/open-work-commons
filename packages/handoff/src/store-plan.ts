import {
  canonicalJsonBytes,
  DEFAULT_VERIFIER_LIMITS,
  isSafeArchivePath,
  parseJsonSafely,
  sha256,
  verifyLogicalArchive,
  type ArchiveManifest,
  type Digest,
  type LogicalArchive,
} from "../../archive/src/index.js";
import { blobRelativePath, type StorePolicy } from "../../store/src/index.js";

import {
  HandoffError,
  type ApprovedStoreBlob,
  type ApprovedStoreEvent,
  type ExactHandoffStorePolicy,
  type HandoffStorePersistenceResult,
  type HandoffStoreWritePlan,
  type HandoffStoreWriter,
  type NormalizedHandoffEvent,
} from "./types.js";
import { isDigest } from "./validation.js";

const MANIFEST_MEDIA_TYPE =
  "application/vnd.openworkcommons.archive-manifest+json";
const JSON_LIMITS = {
  maxDepth: 64,
  maxStringBytes: 1024 * 1024,
} as const;
const ARCHIVE_ID = /^urn:owc:archive:[a-f0-9]{64}$/;
const SAFE_MEDIA_TYPE = /^[\x21-\x7e]+$/;
const MAX_MEDIA_TYPE_BYTES = 256;
const MAX_HANDOFF_EVENTS = 129;

export function buildStoreWritePlan(
  archive: LogicalArchive,
  events: readonly NormalizedHandoffEvent[],
  approvalDigest: Digest,
  archiveId: string,
): HandoffStoreWritePlan {
  const manifest = parseManifest(archive.manifestBytes);
  if (manifest.archive_id !== archiveId) throw invalidPlan();
  const descriptorByPath = new Map(
    manifest.entries.map((descriptor) => [descriptor.path, descriptor]),
  );
  const blobs: ApprovedStoreBlob[] = [
    blob("archive-manifest.json", MANIFEST_MEDIA_TYPE, archive.manifestBytes),
  ];
  for (const entry of archive.entries) {
    const descriptor = descriptorByPath.get(entry.path);
    if (
      !descriptor ||
      descriptor.digest !== sha256(entry.bytes) ||
      descriptor.byte_length !== entry.bytes.byteLength
    ) {
      throw invalidPlan();
    }
    blobs.push(blob(entry.path, descriptor.media_type, entry.bytes));
    descriptorByPath.delete(entry.path);
  }
  if (descriptorByPath.size !== 0) throw invalidPlan();
  blobs.sort((left, right) =>
    compareStrings(left.archivePath, right.archivePath),
  );

  const eventPlans = events.map((event): ApprovedStoreEvent => ({
    eventId: event.event_id,
    eventDigest: sha256(canonicalJsonBytes(event)),
    event: cloneJson(event),
  }));
  const archivedEventDigests = new Map(
    manifest.entries
      .filter((descriptor) => descriptor.role === "event")
      .map((descriptor) => [descriptor.digest, descriptor.path]),
  );
  for (const event of eventPlans) {
    if (!archivedEventDigests.delete(event.eventDigest)) throw invalidPlan();
  }
  if (archivedEventDigests.size !== 0) throw invalidPlan();

  return {
    format: "open-work-commons-exact-store-write-plan",
    schemaVersion: "0.1",
    approvalDigest,
    archiveId,
    blobs,
    events: eventPlans,
  };
}

/**
 * Build a fail-closed StorePolicy that accepts only the post-approval bytes
 * and normalized events in this one plan. Reads and all transformations are
 * denied. Replays remain allowed so interrupted persistence is idempotent.
 */
export function createExactHandoffStorePolicy(
  plan: HandoffStoreWritePlan,
): ExactHandoffStorePolicy {
  const checked = validateAndClonePlan(plan);
  const blobs = new Map<string, Uint8Array>();
  for (const item of checked.blobs) {
    blobs.set(blobKey(item.digest, item.mediaType), new Uint8Array(item.bytes));
  }
  const events = new Map<string, NormalizedHandoffEvent>();
  for (const item of checked.events) {
    events.set(item.eventDigest, cloneJson(item.event));
  }

  const policy: StorePolicy = {
    authorizeAndRedactBlob(input) {
      const digest = sha256(input.bytes);
      const expected = blobs.get(blobKey(digest, input.mediaType));
      if (!expected || !sameBytes(expected, input.bytes)) {
        return { decision: "deny" };
      }
      return { decision: "allow", value: new Uint8Array(expected) };
    },
    authorizeAndRedactEvent(input) {
      let digest: Digest;
      try {
        digest = sha256(canonicalJsonBytes(input.event));
      } catch {
        return { decision: "deny" };
      }
      const expected = events.get(digest);
      if (!expected) return { decision: "deny" };
      return { decision: "allow", value: cloneJson(expected) };
    },
    authorizeRead() {
      return { decision: "deny" };
    },
  };
  return policy;
}

/**
 * Persist an exact plan through a store already configured with the policy
 * returned by createExactHandoffStorePolicy. Blobs are attempted first, then
 * events in chain order. A retry is safe after any interruption.
 */
export async function persistApprovedHandoff(
  store: HandoffStoreWriter,
  plan: HandoffStoreWritePlan,
): Promise<HandoffStorePersistenceResult> {
  if (
    !store ||
    typeof store.putBlob !== "function" ||
    typeof store.appendEvent !== "function"
  ) {
    throw invalidPlan();
  }
  const checked = validateAndClonePlan(plan);
  const blobResults = [];
  for (const item of checked.blobs) {
    const result = await store.putBlob({
      bytes: new Uint8Array(item.bytes),
      mediaType: item.mediaType,
    });
    if (
      !result ||
      result.digest !== item.digest ||
      result.byteLength !== item.byteLength ||
      result.relativePath !== blobRelativePath(item.digest) ||
      !isDisposition(result.disposition)
    ) {
      throw invalidPlan();
    }
    blobResults.push(result);
  }
  const eventResults = [];
  for (const item of checked.events) {
    const result = await store.appendEvent(cloneJson(item.event));
    if (
      !result ||
      result.eventId !== item.eventId ||
      result.eventDigest !== item.eventDigest ||
      result.sequence !== item.event.sequence ||
      !isDisposition(result.disposition)
    ) {
      throw invalidPlan();
    }
    eventResults.push(result);
  }
  return { blobs: blobResults, events: eventResults };
}

function isDisposition(value: unknown): value is "stored" | "existing" {
  return value === "stored" || value === "existing";
}

function validateAndClonePlan(
  plan: HandoffStoreWritePlan,
): HandoffStoreWritePlan {
  if (
    !plan ||
    plan.format !== "open-work-commons-exact-store-write-plan" ||
    plan.schemaVersion !== "0.1" ||
    !isDigest(plan.approvalDigest) ||
    typeof plan.archiveId !== "string" ||
    !ARCHIVE_ID.test(plan.archiveId) ||
    !Array.isArray(plan.blobs) ||
    plan.blobs.length < 2 ||
    plan.blobs.length > DEFAULT_VERIFIER_LIMITS.maxEntryCount + 1 ||
    !Array.isArray(plan.events) ||
    plan.events.length < 1 ||
    plan.events.length > MAX_HANDOFF_EVENTS
  ) {
    throw invalidPlan();
  }
  const archivePaths = new Set<string>();
  const blobs = plan.blobs.map((item): ApprovedStoreBlob => {
    if (
      !item ||
      typeof item.archivePath !== "string" ||
      (item.archivePath !== "archive-manifest.json" &&
        !isSafeArchivePath(item.archivePath)) ||
      typeof item.mediaType !== "string" ||
      item.mediaType.length < 1 ||
      Buffer.byteLength(item.mediaType, "utf8") > MAX_MEDIA_TYPE_BYTES ||
      !SAFE_MEDIA_TYPE.test(item.mediaType) ||
      !isDigest(item.digest) ||
      !Number.isSafeInteger(item.byteLength) ||
      item.byteLength < 0 ||
      !(item.bytes instanceof Uint8Array) ||
      item.bytes.byteLength !== item.byteLength ||
      sha256(item.bytes) !== item.digest
    ) {
      throw invalidPlan();
    }
    if (archivePaths.has(item.archivePath)) throw invalidPlan();
    archivePaths.add(item.archivePath);
    return { ...item, bytes: new Uint8Array(item.bytes) };
  });
  const eventIds = new Set<string>();
  const eventDigests = new Set<Digest>();
  const events = plan.events.map((item): ApprovedStoreEvent => {
    const computedDigest = eventDigest(item?.event);
    if (
      !item ||
      typeof item.eventId !== "string" ||
      !isDigest(item.eventDigest) ||
      !item.event ||
      item.event.event_id !== item.eventId ||
      computedDigest !== item.eventDigest ||
      eventIds.has(item.eventId) ||
      eventDigests.has(item.eventDigest)
    ) {
      throw invalidPlan();
    }
    eventIds.add(item.eventId);
    eventDigests.add(item.eventDigest);
    return { ...item, event: cloneJson(item.event) };
  });
  for (let index = 0; index < events.length; index += 1) {
    const item = events[index];
    const previous = events[index - 1];
    if (
      !item ||
      item.event.sequence !== index ||
      item.event.previous_event_id !== (previous?.eventId ?? null)
    ) {
      throw invalidPlan();
    }
  }
  validateSignedArchiveProjection(blobs, events, plan.archiveId);
  return {
    format: plan.format,
    schemaVersion: plan.schemaVersion,
    approvalDigest: plan.approvalDigest,
    archiveId: plan.archiveId,
    blobs,
    events,
  };
}

function validateSignedArchiveProjection(
  blobs: readonly ApprovedStoreBlob[],
  events: readonly ApprovedStoreEvent[],
  archiveId: string,
): void {
  const manifestBlob = blobs.find(
    (item) => item.archivePath === "archive-manifest.json",
  );
  if (!manifestBlob || manifestBlob.mediaType !== MANIFEST_MEDIA_TYPE) {
    throw invalidPlan();
  }
  const entryBlobs = blobs.filter(
    (item) => item.archivePath !== "archive-manifest.json",
  );
  let verification;
  try {
    verification = verifyLogicalArchive({
      manifestBytes: new Uint8Array(manifestBlob.bytes),
      entries: entryBlobs.map((item) => ({
        path: item.archivePath,
        bytes: new Uint8Array(item.bytes),
        kind: "file",
      })),
    });
  } catch {
    throw invalidPlan();
  }
  if (
    !verification.integrity.valid ||
    !verification.signer.signatureValid ||
    verification.archive.archiveId !== archiveId ||
    verification.archive.entryCount !== entryBlobs.length
  ) {
    throw invalidPlan();
  }

  const manifest = parseManifest(manifestBlob.bytes);
  if (
    manifest.archive_id !== archiveId ||
    manifest.entries.length !== entryBlobs.length
  ) {
    throw invalidPlan();
  }
  const descriptors = new Map(
    manifest.entries.map((item) => [item.path, item]),
  );
  for (const blobItem of entryBlobs) {
    const descriptor = descriptors.get(blobItem.archivePath);
    if (
      !descriptor ||
      descriptor.media_type !== blobItem.mediaType ||
      descriptor.digest !== blobItem.digest ||
      descriptor.byte_length !== blobItem.byteLength
    ) {
      throw invalidPlan();
    }
    descriptors.delete(blobItem.archivePath);
  }
  if (descriptors.size !== 0) throw invalidPlan();

  const archivedEventDigests = new Set(
    manifest.entries
      .filter((item) => item.role === "event")
      .map((item) => item.digest),
  );
  if (archivedEventDigests.size !== events.length) throw invalidPlan();
  for (const event of events) {
    if (!archivedEventDigests.delete(event.eventDigest)) throw invalidPlan();
  }
  if (archivedEventDigests.size !== 0) throw invalidPlan();
}

function eventDigest(event: unknown): Digest | null {
  try {
    return sha256(canonicalJsonBytes(event));
  } catch {
    return null;
  }
}

function blob(
  archivePath: string,
  mediaType: string,
  input: Uint8Array,
): ApprovedStoreBlob {
  const bytes = new Uint8Array(input);
  return {
    archivePath,
    mediaType,
    digest: sha256(bytes),
    byteLength: bytes.byteLength,
    bytes,
  };
}

function parseManifest(bytes: Uint8Array): ArchiveManifest {
  try {
    const value = parseJsonSafely(bytes, JSON_LIMITS);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError("invalid");
    }
    return value as ArchiveManifest;
  } catch {
    throw invalidPlan();
  }
}

function blobKey(digest: Digest, mediaType: string | null): string {
  return `${digest}\0${mediaType ?? ""}`;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(new TextDecoder().decode(canonicalJsonBytes(value))) as T;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalidPlan(): HandoffError {
  return new HandoffError(
    "store_plan_invalid",
    "The exact approved store-write plan is invalid or inconsistent.",
  );
}
