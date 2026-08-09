import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { canonicalJsonBytes } from "../../archive/src/canonical-json.js";

import {
  LocalStoreError,
  LocalWorkspaceStore,
  blobRelativePath,
  sha256Digest,
  type Digest,
  type NormalizedEventEnvelope,
  type PolicyDecision,
  type StorePolicy,
} from "./index.js";
import { hasExpectedPosixOwnerAndMode } from "./filesystem.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test("initializes a private workspace and preserves it across reopen", async () => {
  const workspace = await temporaryWorkspace();
  const policy = allowPolicy();
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });

  const blobBytes = Buffer.from("authorized artifact bytes", "utf8");
  const blob = await store.putBlob({
    bytes: blobBytes,
    mediaType: "text/plain",
  });
  const event = eventEnvelope({
    payload: {
      media_type: "text/plain",
      digest: blob.digest,
      path: blob.relativePath,
    },
  });
  const appended = await store.appendEvent(event);
  assert.equal(appended.disposition, "stored");

  const reopened = await LocalWorkspaceStore.open(workspace, { policy });
  assert.deepEqual(
    Buffer.from(await reopened.readBlob(blob.digest)),
    blobBytes,
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(await reopened.readEvent(event.event_id))),
    event,
  );
  assert.deepEqual(await reopened.healthCheck(), {
    ok: true,
    checkedEvents: 1,
    checkedBlobs: 1,
    issues: [],
  });
});

test("uses restrictive directory and file permissions where modes are supported", async (context) => {
  if (process.platform === "win32") {
    context.skip("Windows does not enforce POSIX owner modes.");
    return;
  }
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const blob = await store.putBlob({ bytes: Buffer.from("private") });
  const event = eventEnvelope();
  await store.appendEvent(event);

  for (const directory of [
    join(workspace, ".owc"),
    join(workspace, ".owc", "events"),
    join(workspace, ".owc", "blobs"),
    join(workspace, ".owc", "blobs", "sha256"),
    join(workspace, ".owc", "blobs", "sha256", blob.digest.slice(7, 9)),
  ]) {
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
  }

  assert.equal(
    (await stat(join(workspace, ".owc", "format.json"))).mode & 0o777,
    0o600,
  );
  const eventFile = (await readdir(join(workspace, ".owc", "events")))[0];
  assert.ok(eventFile);
  assert.equal(
    (await stat(join(workspace, ".owc", "events", eventFile))).mode & 0o777,
    0o600,
  );
  assert.equal(
    (await stat(join(workspace, ".owc", ...blob.relativePath.split("/"))))
      .mode & 0o777,
    0o600,
  );
});

test("rejects weak existing directories instead of repairing their modes", async () => {
  const workspace = await temporaryWorkspace();
  const storeRoot = join(workspace, ".owc");
  await mkdir(storeRoot, { mode: 0o755 });
  await chmod(storeRoot, 0o755);

  await assert.rejects(
    LocalWorkspaceStore.initialize(workspace, { policy: allowPolicy() }),
    storeError("invalid_workspace"),
  );
  assert.equal((await stat(storeRoot)).mode & 0o7777, 0o755);
});

test("fails closed on weak directory and file modes for open, reads, writes, and health", async () => {
  const workspace = await temporaryWorkspace();
  let blobPolicyCalls = 0;
  const policy = allowPolicy({
    authorizeAndRedactBlob: (input) => {
      blobPolicyCalls += 1;
      return { decision: "allow", value: input.bytes };
    },
  });
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });
  const blob = await store.putBlob({ bytes: Buffer.from("private-mode") });
  const event = eventEnvelope();
  await store.appendEvent(event);

  const eventsPath = join(workspace, ".owc", "events");
  await chmod(eventsPath, 0o755);
  await assert.rejects(
    LocalWorkspaceStore.open(workspace, { policy }),
    storeError("invalid_workspace"),
  );
  const policyCallsBeforeRejectedWrite = blobPolicyCalls;
  await assert.rejects(
    store.putBlob({ bytes: Buffer.from("must-not-reach-policy") }),
    storeError("invalid_workspace"),
  );
  assert.equal(blobPolicyCalls, policyCallsBeforeRejectedWrite);
  const directoryReport = await store.healthCheck();
  assert.equal(directoryReport.ok, false);
  assert.equal(directoryReport.checkedEvents, 0);
  assert.equal(directoryReport.checkedBlobs, 0);
  assert.ok(
    directoryReport.issues.some(
      (issue) => issue.code === "workspace_permissions_invalid",
    ),
  );

  await chmod(eventsPath, 0o700);
  const blobPath = join(workspace, ".owc", ...blob.relativePath.split("/"));
  const eventName = (await readdir(eventsPath))[0];
  assert.ok(eventName);
  const eventPath = join(eventsPath, eventName);
  await chmod(blobPath, 0o644);
  await chmod(eventPath, 0o640);

  await assert.rejects(
    LocalWorkspaceStore.open(workspace, { policy }),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.readBlob(blob.digest),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.readEvent(event.event_id),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.appendEvent(event),
    storeError("integrity_failure"),
  );
  const fileReport = await store.healthCheck();
  assert.equal(fileReport.ok, false);
  assert.equal(fileReport.checkedEvents, 0);
  assert.equal(fileReport.checkedBlobs, 0);
  assert.equal(
    fileReport.issues.filter(
      (issue) => issue.code === "workspace_permissions_invalid",
    ).length,
    2,
  );
});

test("does not traverse a weak content-address prefix directory", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const blob = await store.putBlob({ bytes: Buffer.from("prefix-canary") });
  const prefixPath = join(
    workspace,
    ".owc",
    "blobs",
    "sha256",
    blob.digest.slice(7, 9),
  );
  await chmod(prefixPath, 0o755);

  await assert.rejects(
    LocalWorkspaceStore.open(workspace, { policy: allowPolicy() }),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.readBlob(blob.digest),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.putBlob({ bytes: Buffer.from("prefix-canary") }),
    storeError("integrity_failure"),
  );
  const report = await store.healthCheck();
  assert.equal(report.ok, false);
  assert.equal(report.checkedBlobs, 0);
  assert.ok(
    report.issues.some(
      (issue) => issue.code === "workspace_permissions_invalid",
    ),
  );
  assert.equal(JSON.stringify(report).includes("prefix-canary"), false);
});

test("rejects hard-linked content files without reading or reusing them", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const blob = await store.putBlob({ bytes: Buffer.from("hardlink-canary") });
  const event = eventEnvelope();
  await store.appendEvent(event);
  const blobPath = join(workspace, ".owc", ...blob.relativePath.split("/"));
  const eventName = (await readdir(join(workspace, ".owc", "events")))[0];
  assert.ok(eventName);
  const eventPath = join(workspace, ".owc", "events", eventName);
  await link(blobPath, join(workspace, "outside-blob-link"));
  await link(eventPath, join(workspace, "outside-event-link"));

  await assert.rejects(
    store.readBlob(blob.digest),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.readEvent(event.event_id),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.putBlob({ bytes: Buffer.from("hardlink-canary") }),
    storeError("integrity_failure"),
  );
  const report = await store.healthCheck();
  assert.equal(report.ok, false);
  assert.equal(report.checkedEvents, 0);
  assert.equal(report.checkedBlobs, 0);
  assert.ok(report.issues.some((issue) => issue.code === "special_entry"));
  assert.equal(JSON.stringify(report).includes("hardlink-canary"), false);
});

test("rejects weak or hard-linked format markers and unsafe writer locks", async () => {
  const weakWorkspace = await temporaryWorkspace();
  const weakStore = await LocalWorkspaceStore.initialize(weakWorkspace, {
    policy: allowPolicy(),
  });
  await chmod(join(weakWorkspace, ".owc", "format.json"), 0o644);
  await assert.rejects(
    LocalWorkspaceStore.open(weakWorkspace, { policy: allowPolicy() }),
    storeError("integrity_failure"),
  );
  const weakReport = await weakStore.healthCheck();
  assert.equal(weakReport.ok, false);
  assert.equal(weakReport.checkedEvents, 0);
  assert.equal(weakReport.checkedBlobs, 0);
  assert.ok(
    weakReport.issues.some(
      (issue) => issue.code === "workspace_permissions_invalid",
    ),
  );

  const linkedWorkspace = await temporaryWorkspace();
  const linkedStore = await LocalWorkspaceStore.initialize(linkedWorkspace, {
    policy: allowPolicy(),
  });
  await link(
    join(linkedWorkspace, ".owc", "format.json"),
    join(linkedWorkspace, "format-hard-link"),
  );
  await assert.rejects(
    LocalWorkspaceStore.open(linkedWorkspace, { policy: allowPolicy() }),
    storeError("integrity_failure"),
  );
  const linkedReport = await linkedStore.healthCheck();
  assert.equal(linkedReport.ok, false);
  assert.equal(linkedReport.checkedEvents, 0);
  assert.equal(linkedReport.checkedBlobs, 0);
  assert.ok(
    linkedReport.issues.some(
      (issue) => issue.code === "workspace_layout_invalid",
    ),
  );

  const lockWorkspace = await temporaryWorkspace();
  const lockStore = await LocalWorkspaceStore.initialize(lockWorkspace, {
    policy: allowPolicy(),
  });
  const lockSource = join(lockWorkspace, "lock-source");
  await writeFile(lockSource, "", { mode: 0o600 });
  await chmod(lockSource, 0o600);
  await link(lockSource, join(lockWorkspace, ".owc", "write.lock"));
  await assert.rejects(
    lockStore.putBlob({ bytes: Buffer.from("must-not-write") }),
    storeError("integrity_failure"),
  );
  const lockReport = await lockStore.healthCheck();
  assert.equal(lockReport.ok, false);
  assert.equal(lockReport.checkedEvents, 0);
  assert.equal(lockReport.checkedBlobs, 0);
  assert.ok(lockReport.issues.some((issue) => issue.code === "special_entry"));
});

test("checks foreign ownership with a pure non-privileged predicate", () => {
  const currentUid = process.getuid?.();
  assert.notEqual(currentUid, undefined);
  if (currentUid === undefined) return;

  const privateCurrentOwner = { mode: 0o100600, uid: currentUid };
  const privateForeignOwner = { mode: 0o100600, uid: currentUid + 1 };
  const weakCurrentOwner = { mode: 0o100640, uid: currentUid };
  assert.equal(
    hasExpectedPosixOwnerAndMode(privateCurrentOwner, 0o600, currentUid),
    true,
  );
  assert.equal(
    hasExpectedPosixOwnerAndMode(privateForeignOwner, 0o600, currentUid),
    false,
  );
  assert.equal(
    hasExpectedPosixOwnerAndMode(weakCurrentOwner, 0o600, currentUid),
    false,
  );
});

test("allows one opaque device identity subtree but rejects sibling root junk", async () => {
  const workspace = await temporaryWorkspace();
  const policy = allowPolicy();
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });
  const devicePath = join(workspace, ".owc", "device");
  await mkdir(devicePath, { mode: 0o700 });
  await chmod(devicePath, 0o700);
  // Store owns only this top-level boundary. Identity validates its contents.
  await writeFile(join(devicePath, "opaque-identity-owned-entry"), "opaque", {
    mode: 0o644,
  });

  await LocalWorkspaceStore.open(workspace, { policy });
  assert.deepEqual(await store.healthCheck(), {
    ok: true,
    checkedEvents: 0,
    checkedBlobs: 0,
    issues: [],
  });

  await writeFile(join(workspace, ".owc", "sibling-junk"), "junk", {
    mode: 0o600,
  });
  await assert.rejects(
    LocalWorkspaceStore.open(workspace, { policy }),
    storeError("integrity_failure"),
  );
  const report = await store.healthCheck();
  assert.equal(report.ok, false);
  assert.equal(report.checkedEvents, 0);
  assert.equal(report.checkedBlobs, 0);
  assert.ok(report.issues.some((issue) => issue.code === "unexpected_entry"));
});

test("addresses the exact policy-authorized bytes and never the rejected source bytes", async () => {
  const workspace = await temporaryWorkspace();
  const policy = allowPolicy({
    authorizeAndRedactBlob: () => ({
      decision: "allow",
      value: Buffer.from("authorized-redaction", "utf8"),
    }),
  });
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });
  const result = await store.putBlob({
    bytes: Buffer.from("source-secret", "utf8"),
  });
  const expected = `sha256:${createHash("sha256")
    .update("authorized-redaction")
    .digest("hex")}`;

  assert.equal(result.digest, expected);
  assert.equal(result.relativePath, blobRelativePath(expected as Digest));
  assert.equal(
    Buffer.from(await store.readBlob(result.digest)).toString("utf8"),
    "authorized-redaction",
  );
  assert.equal(
    (await allDurableBytes(join(workspace, ".owc"))).includes("source-secret"),
    false,
  );
});

test("replays identical blobs and events idempotently and rejects immutable conflicts", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const bytes = Buffer.from("same bytes");
  assert.equal((await store.putBlob({ bytes })).disposition, "stored");
  assert.equal((await store.putBlob({ bytes })).disposition, "existing");

  const event = eventEnvelope();
  assert.equal((await store.appendEvent(event)).disposition, "stored");
  assert.equal((await store.appendEvent(event)).disposition, "existing");

  const conflicting = eventEnvelope({
    event_id: event.event_id,
    payload: inlinePayload({ objective: "different" }),
  });
  await assert.rejects(store.appendEvent(conflicting), storeError("conflict"));
  assert.equal((await readdir(join(workspace, ".owc", "events"))).length, 1);
});

test("rejects wrong inline digests and sequence conflicts without partial events", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const first = eventEnvelope();
  await store.appendEvent(first);

  const wrongDigest = eventEnvelope({
    event_id: "urn:owc:event:wrong-digest",
    sequence: 1,
    previous_event_id: first.event_id,
    payload: {
      ...inlinePayload({ safe: true }),
      digest: `sha256:${"0".repeat(64)}`,
    },
  });
  await assert.rejects(store.appendEvent(wrongDigest), storeError("conflict"));

  const wrongSequence = eventEnvelope({
    event_id: "urn:owc:event:wrong-sequence",
    sequence: 3,
    previous_event_id: first.event_id,
  });
  await assert.rejects(
    store.appendEvent(wrongSequence),
    storeError("conflict"),
  );
  assert.equal((await readdir(join(workspace, ".owc", "events"))).length, 1);
});

test("rejects impossible RFC3339 calendar dates, times, offsets, and lexical variants", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const invalidDateTimes = [
    "2026-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2026-00-01T12:00:00Z",
    "2026-13-01T12:00:00Z",
    "2026-01-00T12:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T23:60:00Z",
    "2026-01-01T12:00:60Z",
    "2026-01-01T23:59:61Z",
    "2026-01-01T12:00:00+24:00",
    "2026-01-01T12:00:00-00:60",
    "2026-01-01t12:00:00z",
    "2026-01-01 12:00:00Z",
    "2026-01-01T12:00:00+0100",
  ] as const;

  for (const [index, value] of invalidDateTimes.entries()) {
    await assert.rejects(
      store.appendEvent(
        eventEnvelope({
          event_id: `urn:owc:event:invalid-date-${index}`,
          recorded_at: value,
        }),
      ),
      storeError("invalid_input"),
    );
  }
  await assert.rejects(
    store.appendEvent(eventEnvelope({ effective_at: "2026-04-31T12:00:00Z" })),
    storeError("invalid_input"),
  );
  await assert.rejects(
    store.appendEvent(
      eventEnvelope({
        retention: {
          class: "checkpoint",
          expires_at: "2026-02-29T12:00:00Z",
        },
      }),
    ),
    storeError("invalid_input"),
  );
  assert.equal((await readdir(join(workspace, ".owc", "events"))).length, 0);
});

test("accepts RFC3339 leap years, leap seconds, and calendar/timezone boundaries", async () => {
  const validDateTimes = [
    "0000-01-01T00:00:00Z",
    "1900-02-28T00:00:00-23:59",
    "2000-02-29T23:59:59.999+23:59",
    "2024-02-29T12:34:56Z",
    "1990-12-31T23:59:60Z",
    "9999-12-31T23:59:59Z",
  ] as const;

  for (const [index, value] of validDateTimes.entries()) {
    const workspace = await temporaryWorkspace();
    const store = await LocalWorkspaceStore.initialize(workspace, {
      policy: allowPolicy(),
    });
    const result = await store.appendEvent(
      eventEnvelope({
        event_id: `urn:owc:event:valid-date-${index}`,
        recorded_at: value,
        effective_at: value,
        retention: { class: "checkpoint", expires_at: value },
      }),
    );
    assert.equal(result.disposition, "stored");
  }
});

test("accepts only core or reverse-DNS-namespaced event types", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  await assert.rejects(
    store.appendEvent(eventEnvelope({ event_type: "session.paused" })),
    storeError("invalid_input"),
  );
  await assert.rejects(
    store.appendEvent(eventEnvelope({ event_type: "example/session.paused" })),
    storeError("invalid_input"),
  );

  const extension = eventEnvelope({
    event_id: "urn:owc:event:namespaced-type",
    event_type: "org.openworkcommons/session.paused",
  });
  assert.equal((await store.appendEvent(extension)).disposition, "stored");
});

test("failing and interrupted policies leave no lock, temporary file, or final content", async () => {
  const workspace = await temporaryWorkspace();
  let rejectPolicy: ((error: Error) => void) | undefined;
  const policy = allowPolicy({
    authorizeAndRedactBlob: () =>
      new Promise<PolicyDecision<Uint8Array>>((_, reject) => {
        rejectPolicy = reject;
      }),
    authorizeAndRedactEvent: async () => {
      await Promise.resolve();
      throw new Error("untrusted-policy-detail");
    },
  });
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });
  const before = await durableFileInventory(join(workspace, ".owc"));

  const pending = store.putBlob({ bytes: Buffer.from("never-durable") });
  await waitFor(() => rejectPolicy !== undefined);
  assert.deepEqual(await durableFileInventory(join(workspace, ".owc")), before);
  assert.ok(rejectPolicy);
  rejectPolicy(new Error("untrusted-interruption-detail"));
  await assert.rejects(pending, storeError("policy_failure"));
  await assert.rejects(
    store.appendEvent(eventEnvelope()),
    storeError("policy_failure"),
  );

  assert.deepEqual(await durableFileInventory(join(workspace, ".owc")), before);
  const durable = await allDurableBytes(join(workspace, ".owc"));
  assert.equal(durable.includes("never-durable"), false);
  assert.equal(durable.includes("untrusted-"), false);
});

test("rejects traversal-shaped event and payload identifiers without escaping the store", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const traversal = {
    ...eventEnvelope(),
    event_id: "../../outside",
  };
  await assert.rejects(
    store.appendEvent(traversal),
    storeError("invalid_input"),
  );

  const digest = `sha256:${"1".repeat(64)}` as Digest;
  const unsafePayload = eventEnvelope({
    event_id: "urn:owc:event:unsafe-path",
    payload: {
      media_type: "application/octet-stream",
      digest,
      path: "../../outside",
    },
  });
  await assert.rejects(
    store.appendEvent(unsafePayload),
    storeError("invalid_input"),
  );
  assert.equal((await readdir(join(workspace, ".owc", "events"))).length, 0);
  assert.equal(await pathExistsForTest(join(workspace, "outside")), false);
});

test("enforces raw and policy-produced resource limits before durable content writes", async () => {
  const workspace = await temporaryWorkspace();
  let blobPolicyCalls = 0;
  const policy = allowPolicy({
    authorizeAndRedactBlob: (input) => {
      blobPolicyCalls += 1;
      return {
        decision: "allow",
        value: input.bytes.byteLength === 1 ? Buffer.alloc(9) : input.bytes,
      };
    },
  });
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy,
    limits: {
      maxBlobBytes: 8,
      maxEventBytes: 700,
      maxJsonStringBytes: 4096,
    },
  });

  await assert.rejects(
    store.putBlob({ bytes: Buffer.alloc(9) }),
    storeError("resource_limit"),
  );
  assert.equal(blobPolicyCalls, 0);
  await assert.rejects(
    store.putBlob({ bytes: Buffer.alloc(1) }),
    storeError("resource_limit"),
  );
  assert.equal(blobPolicyCalls, 1);
  const oversizedEvent = eventEnvelope({
    payload: inlinePayload({ text: "x".repeat(1000) }),
  });
  await assert.rejects(
    store.appendEvent(oversizedEvent),
    storeError("resource_limit"),
  );
  assert.equal((await readdir(join(workspace, ".owc", "events"))).length, 0);
  assert.equal(
    (await readdir(join(workspace, ".owc", "blobs", "sha256"))).length,
    0,
  );
});

test("secret canaries are absent after policy redaction and rejection", async () => {
  const workspace = await temporaryWorkspace();
  const canary = "OWC_SECRET_CANARY_9ba93a";
  const redactedInline = { note: "[REDACTED]" };
  const policy = allowPolicy({
    authorizeAndRedactBlob: () => ({
      decision: "allow",
      value: Buffer.from("[REDACTED]"),
    }),
    authorizeAndRedactEvent: ({ event }) => {
      const redacted = structuredClone(event) as Record<string, unknown>;
      redacted.payload = inlinePayload(redactedInline);
      return { decision: "allow", value: redacted };
    },
  });
  const store = await LocalWorkspaceStore.initialize(workspace, { policy });
  await store.putBlob({ bytes: Buffer.from(canary) });
  await store.appendEvent(
    eventEnvelope({ payload: inlinePayload({ note: canary }) }),
  );

  const denyPolicy = allowPolicy({
    authorizeAndRedactBlob: () => ({ decision: "deny" }),
  });
  const reopened = await LocalWorkspaceStore.open(workspace, {
    policy: denyPolicy,
  });
  const denied = reopened.putBlob({ bytes: Buffer.from(`${canary}-denied`) });
  await assert.rejects(denied, (error: unknown) => {
    assert.ok(error instanceof LocalStoreError);
    assert.equal(error.code, "policy_denied");
    assert.equal(error.message.includes(canary), false);
    return true;
  });

  assert.equal(
    (await allDurableBytes(join(workspace, ".owc"))).includes(canary),
    false,
  );
});

test("read authorization fails closed without returning stored bytes", async () => {
  const workspace = await temporaryWorkspace();
  const writer = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const blob = await writer.putBlob({ bytes: Buffer.from("private-read") });
  const event = eventEnvelope();
  await writer.appendEvent(event);
  const reader = await LocalWorkspaceStore.open(workspace, {
    policy: allowPolicy({
      authorizeRead: () => ({ decision: "deny" }),
    }),
  });

  await assert.rejects(
    reader.readBlob(blob.digest),
    storeError("policy_denied"),
  );
  await assert.rejects(
    reader.readEvent(event.event_id),
    storeError("policy_denied"),
  );
});

test("offline health check detects content-address tampering without rendering content", async () => {
  const workspace = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const blob = await store.putBlob({ bytes: Buffer.from("original") });
  const event = eventEnvelope();
  await store.appendEvent(event);
  await writeFile(
    join(workspace, ".owc", ...blob.relativePath.split("/")),
    "tampered-secret-payload",
  );
  const eventDirectory = join(workspace, ".owc", "events");
  const eventFile = (await readdir(eventDirectory))[0];
  assert.ok(eventFile);
  const tamperedEvent = JSON.parse(
    (await readFile(join(eventDirectory, eventFile))).toString("utf8"),
  ) as Record<string, unknown>;
  tamperedEvent.subject = {
    kind: "session",
    id: "tampered-event-secret",
  };
  await writeFile(
    join(eventDirectory, eventFile),
    canonicalJsonBytes(tamperedEvent),
  );

  const report = await store.healthCheck();
  assert.equal(report.ok, false);
  assert.ok(
    report.issues.some((issue) => issue.code === "blob_digest_mismatch"),
  );
  assert.ok(
    report.issues.some((issue) => issue.code === "event_path_mismatch"),
  );
  assert.equal(
    JSON.stringify(report).includes("tampered-secret-payload"),
    false,
  );
  assert.equal(JSON.stringify(report).includes("tampered-event-secret"), false);
  await assert.rejects(
    store.readBlob(blob.digest),
    storeError("integrity_failure"),
  );
  await assert.rejects(
    store.readEvent(event.event_id),
    storeError("integrity_failure"),
  );
});

test("health check refuses to traverse a replaced store directory", async (context) => {
  if (process.platform === "win32") {
    context.skip(
      "Creating directory symlinks may require elevated privileges.",
    );
    return;
  }
  const workspace = await temporaryWorkspace();
  const outside = await temporaryWorkspace();
  const store = await LocalWorkspaceStore.initialize(workspace, {
    policy: allowPolicy(),
  });
  const canary = "OUTSIDE_STORE_CANARY";
  await writeFile(join(outside, "outside-event.json"), canary);
  await rm(join(workspace, ".owc", "events"), {
    recursive: true,
    force: true,
  });
  await symlink(outside, join(workspace, ".owc", "events"), "dir");

  const report = await store.healthCheck();
  assert.equal(report.ok, false);
  assert.equal(report.checkedEvents, 0);
  assert.equal(report.checkedBlobs, 0);
  assert.ok(
    report.issues.some((issue) => issue.code === "workspace_layout_invalid"),
  );
  assert.equal(JSON.stringify(report).includes(canary), false);
  await assert.rejects(
    store.appendEvent(eventEnvelope()),
    storeError("invalid_workspace"),
  );
});

function allowPolicy(overrides: Partial<StorePolicy> = {}): StorePolicy {
  return {
    authorizeAndRedactBlob: (input) => ({
      decision: "allow",
      value: input.bytes,
    }),
    authorizeAndRedactEvent: (input) => ({
      decision: "allow",
      value: input.event,
    }),
    authorizeRead: () => ({ decision: "allow" }),
    ...overrides,
  };
}

function eventEnvelope(
  overrides: Partial<NormalizedEventEnvelope> = {},
): NormalizedEventEnvelope {
  return {
    schema_version: "0.1",
    event_id: "urn:owc:event:test-0001",
    event_type: "session.started",
    recorded_at: "2026-08-07T12:00:00Z",
    actor: { id: "urn:owc:actor:test", kind: "human" },
    space_id: "urn:owc:space:test",
    session_id: "urn:owc:session:test",
    sequence: 0,
    previous_event_id: null,
    provider: { name: "owc-test", adapter_version: "0.1.0" },
    subject: { kind: "session", id: "urn:owc:session:test" },
    payload: inlinePayload({ objective: "Test the private local store." }),
    sensitivity: "private",
    retention: { class: "checkpoint", expires_at: null },
    ...overrides,
  };
}

function inlinePayload(value: unknown): {
  readonly media_type: string;
  readonly digest: Digest;
  readonly inline: unknown;
} {
  return {
    media_type: "application/json",
    digest: sha256Digest(canonicalJsonBytes(value)),
    inline: value,
  };
}

function storeError(
  code: LocalStoreError["code"],
): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof LocalStoreError);
    assert.equal(error.code, code);
    return true;
  };
}

async function temporaryWorkspace(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "owc-store-test-"));
  temporaryDirectories.push(path);
  return path;
}

async function durableFileInventory(root: string): Promise<readonly string[]> {
  const output: string[] = [];
  await walk(root, async (path, relative) => {
    const status = await stat(path);
    if (status.isFile()) output.push(relative);
  });
  return output.sort();
}

async function allDurableBytes(root: string): Promise<string> {
  const chunks: Buffer[] = [];
  await walk(root, async (path) => {
    const status = await stat(path);
    if (status.isFile()) chunks.push(await readFile(path));
  });
  return Buffer.concat(chunks).toString("utf8");
}

async function walk(
  root: string,
  visit: (path: string, relative: string) => Promise<void>,
  relative = "",
): Promise<void> {
  const path = relative ? join(root, relative) : root;
  const status = await stat(path);
  if (!status.isDirectory()) {
    await visit(path, relative);
    return;
  }
  for (const entry of await readdir(path)) {
    await walk(root, visit, relative ? join(relative, entry) : entry);
  }
}

async function pathExistsForTest(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.fail("Timed out waiting for the asynchronous test condition.");
}
