import { lstat, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

import { canonicalJsonBytes } from "../../archive/src/canonical-json.js";

import {
  blobRelativePath,
  eventStorageKey,
  sha256Digest,
  sha256Hex,
} from "./crypto.js";
import { LocalStoreError, asSafeStoreError } from "./errors.js";
import {
  assertPrivateDirectory,
  assertSupportedLocalStorePlatform,
  atomicWritePrivateFile,
  ensurePrivateDirectory,
  inspectPrivateDirectory,
  inspectPrivateRegularFile,
  listDirectory,
  pathExists,
  readRegularFileBounded,
  withExclusiveWriteLock,
} from "./filesystem.js";
import type {
  BlobWriteInput,
  BlobWriteResult,
  Digest,
  EventAppendResult,
  HealthIssueCode,
  NormalizedEventEnvelope,
  StoreHealthIssue,
  StoreHealthReport,
  StoreLimits,
  StorePolicy,
  StoreReadRequest,
  WorkspaceStoreOptions,
} from "./types.js";
import {
  boundedPolicyEventClone,
  isDigest,
  validateAuthorizedEvent,
  validateEventId,
  validateStoredEventBytes,
  type ValidatedEvent,
} from "./validation.js";

const STORE_DIRECTORY = ".owc";
const FORMAT_FILE = "format.json";
const EVENT_FILE = /^([a-f0-9]{64})-([a-f0-9]{64})\.json$/;
const BLOB_PREFIX_DIRECTORY = /^[a-f0-9]{2}$/;
const BLOB_FILE = /^[a-f0-9]{62}$/;

const FORMAT_BYTES = canonicalJsonBytes({
  format: "open-work-commons-local-store",
  schema_version: "0.1",
});

export const DEFAULT_STORE_LIMITS: StoreLimits = Object.freeze({
  maxBlobBytes: 16 * 1024 * 1024,
  maxEventBytes: 1024 * 1024,
  maxJsonDepth: 64,
  maxJsonStringBytes: 512 * 1024,
  maxEvents: 100_000,
  maxBlobs: 100_000,
  maxHealthIssues: 100,
});

interface StoredEvent extends ValidatedEvent {
  readonly storageKey: string;
}

export class LocalWorkspaceStore {
  readonly workspacePath: string;
  readonly storePath: string;
  readonly limits: StoreLimits;

  private constructor(
    workspacePath: string,
    private readonly policy: StorePolicy,
    limits: StoreLimits,
  ) {
    this.workspacePath = workspacePath;
    this.storePath = join(workspacePath, STORE_DIRECTORY);
    this.limits = limits;
  }

  static async initialize(
    workspacePath: string,
    options: WorkspaceStoreOptions,
  ): Promise<LocalWorkspaceStore> {
    const resolvedOptions = resolveOptions(options);
    const root = await resolveWorkspaceRoot(workspacePath);
    const store = new LocalWorkspaceStore(
      root,
      resolvedOptions.policy,
      resolvedOptions.limits,
    );

    await ensurePrivateDirectory(store.storePath);
    await ensurePrivateDirectory(store.eventsPath);
    await ensurePrivateDirectory(store.blobsPath);
    await ensurePrivateDirectory(store.sha256BlobsPath);

    const formatPath = join(store.storePath, FORMAT_FILE);
    if (await pathExists(formatPath)) {
      await assertFormat(formatPath);
    } else {
      await atomicWritePrivateFile(formatPath, FORMAT_BYTES);
    }
    await store.assertLayout();
    return store;
  }

  static async open(
    workspacePath: string,
    options: WorkspaceStoreOptions,
  ): Promise<LocalWorkspaceStore> {
    const resolvedOptions = resolveOptions(options);
    const root = await resolveWorkspaceRoot(workspacePath);
    const store = new LocalWorkspaceStore(
      root,
      resolvedOptions.policy,
      resolvedOptions.limits,
    );
    await store.assertLayout();
    return store;
  }

  async putBlob(input: BlobWriteInput): Promise<BlobWriteResult> {
    await this.assertLayout();
    validateBlobInput(input, this.limits);
    const authorizedBytes = await this.authorizeBlob(input);
    const digest = sha256Digest(authorizedBytes);
    const relativePath = blobRelativePath(digest);
    const targetPath = join(this.storePath, ...relativePath.split("/"));

    return withExclusiveWriteLock(this.storePath, async () => {
      // Policy callbacks are untrusted and may be asynchronous; revalidate the
      // complete boundary after authorization and lock acquisition.
      await this.assertLayout();
      await ensurePrivateDirectory(
        join(this.sha256BlobsPath, digest.slice(7, 9)),
      );
      if (await pathExists(targetPath)) {
        const existing = await readRegularFileBounded(
          targetPath,
          this.limits.maxBlobBytes,
        );
        if (
          sha256Digest(existing) !== digest ||
          !Buffer.from(existing).equals(Buffer.from(authorizedBytes))
        ) {
          throw new LocalStoreError("conflict");
        }
        return {
          digest,
          byteLength: authorizedBytes.byteLength,
          relativePath,
          disposition: "existing",
        };
      }

      await atomicWritePrivateFile(targetPath, authorizedBytes);
      return {
        digest,
        byteLength: authorizedBytes.byteLength,
        relativePath,
        disposition: "stored",
      };
    });
  }

  async appendEvent(input: unknown): Promise<EventAppendResult> {
    await this.assertLayout();
    const proposed = boundedPolicyEventClone(input, this.limits);
    const authorized = await this.authorizeEvent(proposed);

    return withExclusiveWriteLock(this.storePath, async () => {
      await this.assertLayout();
      const storedEvents = await this.loadEventsStrict();
      assertStoredEventChains(storedEvents);

      const existing = storedEvents.find(
        (candidate) => candidate.event.event_id === authorized.event.event_id,
      );
      if (existing) {
        if (
          existing.digest !== authorized.digest ||
          !Buffer.from(existing.bytes).equals(Buffer.from(authorized.bytes))
        ) {
          throw new LocalStoreError("conflict");
        }
        return eventResult(authorized, "existing");
      }

      await this.assertEventCanAppend(authorized.event, storedEvents);
      await this.assertReferencedBlob(authorized.event);

      const targetPath = join(
        this.eventsPath,
        eventFileName(authorized.event.event_id, authorized.digest),
      );
      if (await pathExists(targetPath)) {
        throw new LocalStoreError("conflict");
      }
      await atomicWritePrivateFile(targetPath, authorized.bytes);
      return eventResult(authorized, "stored");
    });
  }

  async readBlob(digest: Digest): Promise<Uint8Array> {
    await this.assertLayout();
    if (!isDigest(digest)) throw new LocalStoreError("invalid_input");
    await this.authorizeRead({ kind: "blob", digest });
    await this.assertLayout();
    const relativePath = blobRelativePath(digest);
    await assertPrivateDirectory(
      join(this.sha256BlobsPath, digest.slice(7, 9)),
    );
    const path = join(this.storePath, ...relativePath.split("/"));
    const bytes = await readRegularFileBounded(path, this.limits.maxBlobBytes);
    if (sha256Digest(bytes) !== digest) {
      throw new LocalStoreError("integrity_failure");
    }
    return new Uint8Array(bytes);
  }

  async readEvent(eventId: string): Promise<NormalizedEventEnvelope> {
    await this.assertLayout();
    validateEventId(eventId);
    await this.authorizeRead({ kind: "event", eventId });
    await this.assertLayout();
    const allStored = await this.loadEventsStrict();
    assertStoredEventChains(allStored);
    const stored = allStored.filter(
      (candidate) => candidate.event.event_id === eventId,
    );
    if (stored.length === 0) throw new LocalStoreError("not_found");
    if (stored.length !== 1) throw new LocalStoreError("integrity_failure");
    const validated = stored[0];
    if (!validated) throw new LocalStoreError("integrity_failure");
    await this.assertReferencedBlob(validated.event);
    return validated.event;
  }

  async healthCheck(): Promise<StoreHealthReport> {
    const issues: StoreHealthIssue[] = [];
    const addIssue = (
      code: HealthIssueCode,
      location: string,
      message: string,
    ): void => {
      if (issues.length < this.limits.maxHealthIssues) {
        issues.push({ code, location, message });
      }
    };

    const layoutSafe = await this.inspectLayout(addIssue);
    if (!layoutSafe) {
      return {
        ok: false,
        checkedEvents: 0,
        checkedBlobs: 0,
        issues,
      };
    }
    const events = await this.inspectEvents(addIssue);
    const blobDigests = await this.inspectBlobs(addIssue);
    inspectChains(events, addIssue);

    for (const stored of events) {
      if (!("path" in stored.event.payload)) continue;
      const digest = stored.event.payload.digest;
      const expectedPath = blobRelativePath(digest);
      if (stored.event.payload.path !== expectedPath) {
        addIssue(
          "event_path_mismatch",
          stored.storageKey,
          "An event payload path does not match its content digest.",
        );
      } else if (!blobDigests.has(digest)) {
        addIssue(
          "blob_missing",
          digest,
          "An event references a missing or invalid blob.",
        );
      }
    }

    return {
      ok: issues.length === 0,
      checkedEvents: events.length,
      checkedBlobs: blobDigests.size,
      issues,
    };
  }

  private get eventsPath(): string {
    return join(this.storePath, "events");
  }

  private get blobsPath(): string {
    return join(this.storePath, "blobs");
  }

  private get sha256BlobsPath(): string {
    return join(this.blobsPath, "sha256");
  }

  private async assertLayout(): Promise<void> {
    await assertPrivateDirectory(this.storePath);
    await assertPrivateDirectory(this.eventsPath);
    await assertPrivateDirectory(this.blobsPath);
    await assertPrivateDirectory(this.sha256BlobsPath);
    await assertFormat(join(this.storePath, FORMAT_FILE));
    await this.assertRootEntries();
    await this.assertStoredPathSecurity();
  }

  private async assertRootEntries(): Promise<void> {
    const entries = await listDirectory(this.storePath);
    for (const entry of entries) {
      if (
        entry.name === FORMAT_FILE ||
        entry.name === "events" ||
        entry.name === "blobs"
      ) {
        continue;
      }
      if (entry.name === "device") {
        await assertPrivateDirectory(join(this.storePath, entry.name));
        continue;
      }
      if (entry.name === "write.lock") {
        if (
          (await inspectPrivateRegularFile(
            join(this.storePath, entry.name),
          )) !== "safe"
        ) {
          throw new LocalStoreError("integrity_failure");
        }
        continue;
      }
      throw new LocalStoreError("integrity_failure");
    }
  }

  private async assertStoredPathSecurity(): Promise<void> {
    const eventEntries = await listDirectory(this.eventsPath);
    if (eventEntries.length > this.limits.maxEvents) {
      throw new LocalStoreError("resource_limit");
    }
    for (const entry of eventEntries) {
      if (
        !entry.isFile() ||
        !EVENT_FILE.test(entry.name) ||
        (await inspectPrivateRegularFile(join(this.eventsPath, entry.name))) !==
          "safe"
      ) {
        throw new LocalStoreError("integrity_failure");
      }
    }

    const prefixes = await listDirectory(this.sha256BlobsPath);
    let seenBlobs = 0;
    for (const prefix of prefixes) {
      const prefixPath = join(this.sha256BlobsPath, prefix.name);
      if (
        !prefix.isDirectory() ||
        !BLOB_PREFIX_DIRECTORY.test(prefix.name) ||
        (await inspectPrivateDirectory(prefixPath)) !== "safe"
      ) {
        throw new LocalStoreError("integrity_failure");
      }
      const entries = await listDirectory(prefixPath);
      seenBlobs += entries.length;
      if (seenBlobs > this.limits.maxBlobs) {
        throw new LocalStoreError("resource_limit");
      }
      for (const entry of entries) {
        if (
          !entry.isFile() ||
          !BLOB_FILE.test(entry.name) ||
          (await inspectPrivateRegularFile(join(prefixPath, entry.name))) !==
            "safe"
        ) {
          throw new LocalStoreError("integrity_failure");
        }
      }
    }
  }

  private async authorizeBlob(input: BlobWriteInput): Promise<Uint8Array> {
    let decision: unknown;
    try {
      decision = await this.policy.authorizeAndRedactBlob({
        bytes: new Uint8Array(input.bytes),
        mediaType: input.mediaType ?? null,
      });
    } catch {
      throw new LocalStoreError("policy_failure");
    }
    const value = allowedPolicyValue<unknown>(decision);
    if (!(value instanceof Uint8Array)) {
      throw new LocalStoreError("policy_failure");
    }
    const bytes = new Uint8Array(value);
    if (bytes.byteLength > this.limits.maxBlobBytes) {
      throw new LocalStoreError("resource_limit");
    }
    return bytes;
  }

  private async authorizeEvent(proposed: unknown): Promise<ValidatedEvent> {
    let decision: unknown;
    try {
      decision = await this.policy.authorizeAndRedactEvent({ event: proposed });
    } catch {
      throw new LocalStoreError("policy_failure");
    }
    const value = allowedPolicyValue<unknown>(decision);
    return validateAuthorizedEvent(value, this.limits);
  }

  private async authorizeRead(request: StoreReadRequest): Promise<void> {
    let decision: unknown;
    try {
      decision = await this.policy.authorizeRead(request);
      if (
        decision === null ||
        typeof decision !== "object" ||
        !("decision" in decision)
      ) {
        throw new LocalStoreError("policy_failure");
      }
      const action = (decision as { readonly decision?: unknown }).decision;
      if (action === "deny") throw new LocalStoreError("policy_denied");
      if (action !== "allow") throw new LocalStoreError("policy_failure");
    } catch (error) {
      throw asSafeStoreError(error, "policy_failure");
    }
  }

  private async loadEventsStrict(): Promise<readonly StoredEvent[]> {
    const entries = await listDirectory(this.eventsPath);
    if (entries.length > this.limits.maxEvents) {
      throw new LocalStoreError("resource_limit");
    }
    const events: StoredEvent[] = [];
    const ids = new Set<string>();
    for (const entry of entries) {
      if (!entry.isFile() || !EVENT_FILE.test(entry.name)) {
        throw new LocalStoreError("integrity_failure");
      }
      const bytes = await readRegularFileBounded(
        join(this.eventsPath, entry.name),
        this.limits.maxEventBytes,
      );
      let validated: ValidatedEvent;
      try {
        validated = validateStoredEventBytes(bytes, this.limits);
      } catch {
        throw new LocalStoreError("integrity_failure");
      }
      const match = EVENT_FILE.exec(entry.name);
      if (!match) throw new LocalStoreError("integrity_failure");
      const storageKey = match[1];
      const filenameDigest = match[2];
      if (!storageKey || !filenameDigest) {
        throw new LocalStoreError("integrity_failure");
      }
      if (
        eventStorageKey(validated.event.event_id) !== storageKey ||
        validated.digest.slice("sha256:".length) !== filenameDigest ||
        ids.has(validated.event.event_id)
      ) {
        throw new LocalStoreError("integrity_failure");
      }
      ids.add(validated.event.event_id);
      events.push({ ...validated, storageKey });
    }
    return events;
  }

  private async assertEventCanAppend(
    event: NormalizedEventEnvelope,
    storedEvents: readonly StoredEvent[],
  ): Promise<void> {
    const session = storedEvents
      .filter((candidate) => candidate.event.session_id === event.session_id)
      .sort((left, right) => left.event.sequence - right.event.sequence);
    const sequenceConflict = session.some(
      (candidate) => candidate.event.sequence === event.sequence,
    );
    if (sequenceConflict) throw new LocalStoreError("conflict");

    const head = session.at(-1);
    if (!head) {
      if (event.sequence !== 0 || event.previous_event_id !== null) {
        throw new LocalStoreError("conflict");
      }
      return;
    }
    if (
      event.sequence !== head.event.sequence + 1 ||
      event.previous_event_id !== head.event.event_id
    ) {
      throw new LocalStoreError("conflict");
    }
  }

  private async assertReferencedBlob(
    event: NormalizedEventEnvelope,
  ): Promise<void> {
    if (!("path" in event.payload)) return;
    const expected = blobRelativePath(event.payload.digest);
    if (event.payload.path !== expected) {
      throw new LocalStoreError("conflict");
    }
    await assertPrivateDirectory(
      join(this.sha256BlobsPath, event.payload.digest.slice(7, 9)),
    );
    const path = join(this.storePath, ...expected.split("/"));
    const bytes = await readRegularFileBounded(path, this.limits.maxBlobBytes);
    if (sha256Digest(bytes) !== event.payload.digest) {
      throw new LocalStoreError("integrity_failure");
    }
  }

  private async inspectLayout(
    addIssue: (
      code: HealthIssueCode,
      location: string,
      message: string,
    ) => void,
  ): Promise<boolean> {
    let safeToTraverse = true;
    const directories = [
      [this.storePath, "store-root"],
      [this.eventsPath, "events"],
      [this.blobsPath, "blobs"],
      [this.sha256BlobsPath, "blobs/sha256"],
    ] as const;
    for (const [path, location] of directories) {
      const safety = await inspectPrivateDirectory(path);
      if (safety === "unsafe_permissions") {
        safeToTraverse = false;
        addIssue(
          "workspace_permissions_invalid",
          location,
          "A store directory is not owner-only or has a foreign owner.",
        );
      } else if (safety !== "safe") {
        safeToTraverse = false;
        addIssue(
          "workspace_layout_invalid",
          location,
          "A required private store directory is missing or unsafe.",
        );
      }
    }

    if (!safeToTraverse) return false;

    const formatPath = join(this.storePath, FORMAT_FILE);
    const formatSafety = await inspectPrivateRegularFile(formatPath);
    if (formatSafety === "unsafe_permissions") {
      addIssue(
        "workspace_permissions_invalid",
        "format",
        "The store format file is not owner-only or has a foreign owner.",
      );
      return false;
    }
    if (formatSafety !== "safe") {
      addIssue(
        "workspace_layout_invalid",
        "format",
        "The store format marker is missing or unsafe.",
      );
      return false;
    }
    try {
      await assertFormat(formatPath);
    } catch {
      addIssue(
        "workspace_layout_invalid",
        "format",
        "The store format marker is invalid.",
      );
      return false;
    }

    const lockSafety = await inspectPrivateRegularFile(
      join(this.storePath, "write.lock"),
    );
    if (lockSafety === "safe") {
      safeToTraverse = false;
      addIssue(
        "store_busy",
        "write-lock",
        "A writer lock is present; the store may be active or need recovery.",
      );
    } else if (lockSafety === "unsafe_permissions") {
      safeToTraverse = false;
      addIssue(
        "workspace_permissions_invalid",
        "write-lock",
        "The writer lock is not owner-only or has a foreign owner.",
      );
    } else if (lockSafety === "unsafe_entry") {
      safeToTraverse = false;
      addIssue(
        "special_entry",
        "write-lock",
        "The writer lock is a symlink, hard link, or special entry.",
      );
    }

    try {
      const entries = await listDirectory(this.storePath);
      const allowed = new Set([
        FORMAT_FILE,
        "events",
        "blobs",
        "write.lock",
        "device",
      ]);
      for (const entry of entries) {
        if (!allowed.has(entry.name)) {
          safeToTraverse = false;
          addIssue(
            "unexpected_entry",
            "store-root",
            "The store root contains an unexpected entry.",
          );
          continue;
        }
        if (entry.name !== "device") continue;
        const deviceSafety = await inspectPrivateDirectory(
          join(this.storePath, "device"),
        );
        if (deviceSafety === "unsafe_permissions") {
          safeToTraverse = false;
          addIssue(
            "workspace_permissions_invalid",
            "device",
            "The opaque device identity boundary is not owner-only or has a foreign owner.",
          );
        } else if (deviceSafety !== "safe") {
          safeToTraverse = false;
          addIssue(
            "special_entry",
            "device",
            "The opaque device identity boundary is not a safe directory.",
          );
        }
      }
    } catch {
      safeToTraverse = false;
      addIssue(
        "workspace_layout_invalid",
        "store-root",
        "The store root cannot be inspected safely.",
      );
    }

    try {
      const entries = await listDirectory(this.blobsPath);
      if (entries.some((entry) => entry.name !== "sha256")) {
        safeToTraverse = false;
        addIssue(
          "unexpected_entry",
          "blobs",
          "The blob root contains an unexpected entry.",
        );
      }
    } catch {
      safeToTraverse = false;
      addIssue(
        "workspace_layout_invalid",
        "blobs",
        "The blob root cannot be inspected safely.",
      );
    }

    return safeToTraverse;
  }

  private async inspectEvents(
    addIssue: (
      code: HealthIssueCode,
      location: string,
      message: string,
    ) => void,
  ): Promise<readonly StoredEvent[]> {
    let entries;
    try {
      entries = await listDirectory(this.eventsPath);
    } catch {
      return [];
    }
    if (entries.length > this.limits.maxEvents) {
      addIssue(
        "resource_limit",
        "events",
        "The event count exceeds the configured health-check limit.",
      );
      entries = entries.slice(0, this.limits.maxEvents);
    }

    const events: StoredEvent[] = [];
    const ids = new Set<string>();
    for (const entry of entries) {
      if (!entry.isFile() || !EVENT_FILE.test(entry.name)) {
        addIssue(
          entry.isSymbolicLink() ? "special_entry" : "unexpected_entry",
          "events",
          "The event directory contains an unsafe entry.",
        );
        continue;
      }
      const match = EVENT_FILE.exec(entry.name);
      if (!match) {
        addIssue(
          "event_invalid",
          "events",
          "A stored event name is structurally invalid.",
        );
        continue;
      }
      const storageKey = match[1];
      const filenameDigest = match[2];
      if (!storageKey || !filenameDigest) continue;
      const path = join(this.eventsPath, entry.name);
      const safety = await inspectPrivateRegularFile(path);
      if (safety === "unsafe_permissions") {
        addIssue(
          "workspace_permissions_invalid",
          storageKey,
          "An event file is not owner-only or has a foreign owner.",
        );
        continue;
      }
      if (safety !== "safe") {
        addIssue(
          "special_entry",
          storageKey,
          "An event file is a symlink, hard link, or special entry.",
        );
        continue;
      }
      try {
        const bytes = await readRegularFileBounded(
          path,
          this.limits.maxEventBytes,
        );
        const validated = validateStoredEventBytes(bytes, this.limits);
        if (
          eventStorageKey(validated.event.event_id) !== storageKey ||
          validated.digest.slice("sha256:".length) !== filenameDigest
        ) {
          addIssue(
            "event_path_mismatch",
            storageKey,
            "An event is stored under the wrong digest-derived key.",
          );
          continue;
        }
        if (ids.has(validated.event.event_id)) {
          addIssue(
            "event_digest_conflict",
            storageKey,
            "An event identifier resolves to more than one stored event.",
          );
          continue;
        }
        ids.add(validated.event.event_id);
        events.push({ ...validated, storageKey });
      } catch (error) {
        addIssue(
          error instanceof LocalStoreError && error.code === "resource_limit"
            ? "resource_limit"
            : "event_invalid",
          storageKey,
          "A stored event is invalid or exceeds its configured limit.",
        );
      }
    }
    return events;
  }

  private async inspectBlobs(
    addIssue: (
      code: HealthIssueCode,
      location: string,
      message: string,
    ) => void,
  ): Promise<ReadonlySet<Digest>> {
    let prefixes;
    try {
      prefixes = await listDirectory(this.sha256BlobsPath);
    } catch {
      return new Set();
    }
    const digests = new Set<Digest>();
    let seen = 0;
    for (const prefix of prefixes) {
      if (!prefix.isDirectory() || !BLOB_PREFIX_DIRECTORY.test(prefix.name)) {
        addIssue(
          prefix.isSymbolicLink() ? "special_entry" : "blob_path_invalid",
          "blobs/sha256",
          "The blob store contains an unsafe prefix entry.",
        );
        continue;
      }
      const prefixPath = join(this.sha256BlobsPath, prefix.name);
      const prefixSafety = await inspectPrivateDirectory(prefixPath);
      if (prefixSafety === "unsafe_permissions") {
        addIssue(
          "workspace_permissions_invalid",
          "blobs/sha256",
          "A blob prefix directory is not owner-only or has a foreign owner.",
        );
        continue;
      }
      if (prefixSafety !== "safe") {
        addIssue(
          "blob_path_invalid",
          "blobs/sha256",
          "A blob prefix directory is missing or unsafe.",
        );
        continue;
      }
      let entries;
      try {
        entries = await listDirectory(prefixPath);
      } catch {
        addIssue(
          "blob_path_invalid",
          "blobs/sha256",
          "A blob prefix directory cannot be inspected safely.",
        );
        continue;
      }
      for (const entry of entries) {
        seen += 1;
        if (seen > this.limits.maxBlobs) {
          addIssue(
            "resource_limit",
            "blobs",
            "The blob count exceeds the configured health-check limit.",
          );
          return digests;
        }
        if (!entry.isFile() || !BLOB_FILE.test(entry.name)) {
          addIssue(
            entry.isSymbolicLink() ? "special_entry" : "blob_path_invalid",
            "blobs/sha256",
            "The blob store contains an unsafe entry.",
          );
          continue;
        }
        const digest = `sha256:${prefix.name}${entry.name}` as Digest;
        const path = join(prefixPath, entry.name);
        const safety = await inspectPrivateRegularFile(path);
        if (safety === "unsafe_permissions") {
          addIssue(
            "workspace_permissions_invalid",
            digest,
            "A blob file is not owner-only or has a foreign owner.",
          );
          continue;
        }
        if (safety !== "safe") {
          addIssue(
            "special_entry",
            digest,
            "A blob file is a symlink, hard link, or special entry.",
          );
          continue;
        }
        try {
          const bytes = await readRegularFileBounded(
            path,
            this.limits.maxBlobBytes,
          );
          if (sha256Digest(bytes) !== digest) {
            addIssue(
              "blob_digest_mismatch",
              digest,
              "A blob does not match its digest-derived path.",
            );
            continue;
          }
          digests.add(digest);
        } catch (error) {
          addIssue(
            error instanceof LocalStoreError && error.code === "resource_limit"
              ? "resource_limit"
              : "blob_digest_mismatch",
            digest,
            "A blob is invalid or exceeds its configured limit.",
          );
        }
      }
    }
    return digests;
  }
}

function resolveOptions(options: WorkspaceStoreOptions): {
  readonly policy: StorePolicy;
  readonly limits: StoreLimits;
} {
  if (
    !options ||
    typeof options !== "object" ||
    !options.policy ||
    typeof options.policy.authorizeAndRedactBlob !== "function" ||
    typeof options.policy.authorizeAndRedactEvent !== "function" ||
    typeof options.policy.authorizeRead !== "function"
  ) {
    throw new LocalStoreError("invalid_input");
  }
  const limits = { ...DEFAULT_STORE_LIMITS, ...options.limits };
  for (const value of Object.values(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new LocalStoreError("invalid_input");
    }
  }
  return { policy: options.policy, limits };
}

async function resolveWorkspaceRoot(workspacePath: string): Promise<string> {
  assertSupportedLocalStorePlatform();
  if (typeof workspacePath !== "string" || workspacePath.length < 1) {
    throw new LocalStoreError("invalid_workspace");
  }
  const candidate = resolve(workspacePath);
  try {
    const status = await lstat(candidate);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new LocalStoreError("invalid_workspace");
    }
    return await realpath(candidate);
  } catch (error) {
    throw asSafeStoreError(error, "invalid_workspace");
  }
}

async function assertFormat(path: string): Promise<void> {
  const bytes = await readRegularFileBounded(path, 4096);
  if (!Buffer.from(bytes).equals(Buffer.from(FORMAT_BYTES))) {
    throw new LocalStoreError("unsupported_store");
  }
}

function validateBlobInput(input: BlobWriteInput, limits: StoreLimits): void {
  if (
    !input ||
    typeof input !== "object" ||
    !(input.bytes instanceof Uint8Array)
  ) {
    throw new LocalStoreError("invalid_input");
  }
  if (input.bytes.byteLength > limits.maxBlobBytes) {
    throw new LocalStoreError("resource_limit");
  }
  if (
    input.mediaType !== undefined &&
    (typeof input.mediaType !== "string" ||
      input.mediaType.length < 1 ||
      input.mediaType.length > 256)
  ) {
    throw new LocalStoreError("invalid_input");
  }
}

function allowedPolicyValue<T>(decision: unknown): T {
  try {
    if (
      decision === null ||
      typeof decision !== "object" ||
      !("decision" in decision)
    ) {
      throw new LocalStoreError("policy_failure");
    }
    const action = (decision as { readonly decision?: unknown }).decision;
    if (action === "deny") throw new LocalStoreError("policy_denied");
    if (action !== "allow" || !("value" in decision)) {
      throw new LocalStoreError("policy_failure");
    }
    return (decision as { readonly value: T }).value;
  } catch (error) {
    throw asSafeStoreError(error, "policy_failure");
  }
}

function eventResult(
  event: ValidatedEvent,
  disposition: "stored" | "existing",
): EventAppendResult {
  return {
    eventId: event.event.event_id,
    eventDigest: event.digest,
    sequence: event.event.sequence,
    disposition,
  };
}

function eventFileName(eventId: string, digest: Digest): string {
  return `${eventStorageKey(eventId)}-${digest.slice("sha256:".length)}.json`;
}

function assertStoredEventChains(events: readonly StoredEvent[]): void {
  const sessions = groupEventsBySession(events);
  for (const session of sessions.values()) {
    session.sort((left, right) => left.event.sequence - right.event.sequence);
    for (let index = 0; index < session.length; index += 1) {
      const current = session[index];
      if (!current) throw new LocalStoreError("integrity_failure");
      const previous = session[index - 1];
      if (
        current.event.sequence !== index ||
        current.event.previous_event_id !== (previous?.event.event_id ?? null)
      ) {
        throw new LocalStoreError("integrity_failure");
      }
    }
  }
}

function inspectChains(
  events: readonly StoredEvent[],
  addIssue: (code: HealthIssueCode, location: string, message: string) => void,
): void {
  const sessions = groupEventsBySession(events);
  for (const [sessionId, session] of sessions) {
    session.sort((left, right) => left.event.sequence - right.event.sequence);
    let invalid = false;
    for (let index = 0; index < session.length; index += 1) {
      const current = session[index];
      const previous = session[index - 1];
      if (
        !current ||
        current.event.sequence !== index ||
        current.event.previous_event_id !== (previous?.event.event_id ?? null)
      ) {
        invalid = true;
        break;
      }
    }
    if (invalid) {
      addIssue(
        "event_chain_invalid",
        sha256Hex(Buffer.from(sessionId, "utf8")),
        "A session event chain has a gap or invalid previous-event reference.",
      );
    }
  }
}

function groupEventsBySession(
  events: readonly StoredEvent[],
): Map<string, StoredEvent[]> {
  const sessions = new Map<string, StoredEvent[]>();
  for (const event of events) {
    const session = sessions.get(event.event.session_id) ?? [];
    session.push(event);
    sessions.set(event.event.session_id, session);
  }
  return sessions;
}
