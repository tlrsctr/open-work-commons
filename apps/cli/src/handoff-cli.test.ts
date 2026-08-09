import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalJsonBytes,
  createSignedArchive,
  generateArchiveSigningKey,
  sha256,
  type GeneratedSigningKey,
  type LogicalArchive,
} from "../../../packages/archive/src/index.js";
import { ExitCode } from "../../../packages/core/src/index.js";
import type { CapturedGitState } from "../../../packages/git-state/src/index.js";
import {
  createApprovedHandoff,
  inspectHandoff,
  type ApprovedHandoff,
  type HandoffStoreWritePlan,
  type OperatorHandoffPlan,
} from "../../../packages/handoff/src/index.js";
import type {
  DeviceSigningIdentity,
  PublicDeviceIdentity,
  UnsignedArchiveInput,
} from "../../../packages/identity/src/index.js";

import { runCli, type CliDependencies } from "./cli.js";
import type { DeviceIdentityRuntime } from "./device-identity-runtime.js";
import { HandoffFileError } from "./handoff-file-runtime.js";
import type { HandoffFileRuntime } from "./handoff-file-runtime.js";
import type { WorkspaceStoreRuntime } from "./store-runtime.js";

const CAPTURED_AT = "2026-08-07T12:00:00Z";
const EXTERNAL_CHECKPOINT_ID = "01KVBJCWYA4YW6J5M9GP655HZN";
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const entireDetail = readFileSync(
  `${repositoryRoot}/packages/adapters/entire/test/fixtures/checkpoint-detail.sanitized.json`,
  "utf8",
);

class TestSigningIdentity implements DeviceSigningIdentity {
  readonly publicIdentity: PublicDeviceIdentity;
  archiveCalls = 0;

  constructor(private readonly key: GeneratedSigningKey) {
    this.publicIdentity = {
      format: "open-work-commons-device-identity",
      schema_version: "0.1",
      algorithm: "ed25519",
      key_id: key.keyId,
      fingerprint: key.fingerprint,
      public_key: key.publicKeyBase64Url,
      public_key_spki: Buffer.from(
        key.publicKey.export({ format: "der", type: "spki" }),
      ).toString("base64url"),
    };
  }

  sign(): string {
    throw new Error("The handoff core must use the archive capability.");
  }

  createSignedArchive(input: UnsignedArchiveInput): LogicalArchive {
    this.archiveCalls += 1;
    return createSignedArchive({
      ...input,
      signingKey: { keyId: this.key.keyId, privateKey: this.key.privateKey },
    });
  }
}

function plan(): OperatorHandoffPlan {
  return {
    source: {
      provider: "entire",
      providerVersion: "0.9.0",
      externalCheckpointId: EXTERNAL_CHECKPOINT_ID,
    },
    actor: { id: "human:test", displayName: "Test operator" },
    spaceId: "space:test",
    work: {
      workItemId: "OWC-12",
      title: "Portable handoff",
      objective: "Resume the exact approved work with another agent.",
      constraints: ["Do not import provider transcripts."],
    },
    decisions: ["Use the provider-neutral archive boundary."],
    openQuestions: ["Will the receiving agent preserve the constraints?"],
    nextAction: "Compile the verified archive for the receiving agent.",
    sensitivity: "private",
    retention: { class: "checkpoint", expiresAt: null },
  };
}

function capturedGit(): CapturedGitState {
  const state = {
    schema_version: "0.1" as const,
    repository_id: "urn:owc:repository:test",
    object_format: "sha1" as const,
    captured_at: CAPTURED_AT,
    base_commit: "1".repeat(40),
    head_commit: "1".repeat(40),
    head_tree: "2".repeat(40),
    head_ref: "refs/heads/main",
    worktree: { clean: true, untracked: [] },
  };
  const stateBytes = canonicalJsonBytes(state);
  return {
    state,
    stateBytes,
    stateDigest: sha256(stateBytes),
    patchArtifact: null,
    untrackedArtifacts: [],
  };
}

type FixtureOptions = {
  readonly identity: TestSigningIdentity;
  readonly calls?: string[];
  readonly storeFailure?: boolean;
  readonly publishFailure?: HandoffFileError["code"];
};

function fixture(options: FixtureOptions) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const calls = options.calls ?? [];
  const git = capturedGit();
  const files: HandoffFileRuntime = {
    async readPlan() {
      calls.push("read-plan");
      return plan();
    },
    async readEntireCheckpointDetail() {
      calls.push("read-entire-detail");
      return entireDetail;
    },
    async assertOutputAvailable() {
      calls.push("preflight-output");
    },
    async publishArchive(_path, archive) {
      calls.push("publish-archive");
      if (options.publishFailure) {
        throw new HandoffFileError(options.publishFailure);
      }
      return {
        entryCount: archive.entries.length,
        totalBytes:
          archive.manifestBytes.byteLength +
          archive.entries.reduce(
            (total, entry) => total + entry.bytes.byteLength,
            0,
          ),
      };
    },
  };
  const identityRuntime: DeviceIdentityRuntime = {
    async openOrCreate() {
      throw new Error("Initialization must not run.");
    },
    async diagnose() {
      calls.push("diagnose-identity");
      return {
        ok: true,
        code: "ready",
        identity: options.identity.publicIdentity,
        message: "The local device identity is ready.",
      };
    },
    async createApprovedHandoff(input) {
      calls.push("sign-approved");
      return createApprovedHandoff({
        ...input,
        signingIdentity: options.identity,
      });
    },
  };
  const store: WorkspaceStoreRuntime = {
    async initialize() {
      throw new Error("Initialization must not run.");
    },
    async health() {
      throw new Error("Health must not run.");
    },
    async persistApprovedHandoff(_workspace, writePlan) {
      calls.push("persist-store");
      if (options.storeFailure) throw new Error("PRIVATE_STORE_FAILURE");
      return persistenceResult(writePlan);
    },
  };
  const dependencies: CliDependencies = {
    cwd: "/private/repository",
    node_version: process.version,
    file_system: {
      async can_access() {
        return true;
      },
    },
    command_runner: {
      async run() {
        calls.push("unexpected-provider-command");
        throw new Error("No Entire command may run during handoff.");
      },
    },
    archive_loader: {
      async load() {
        throw new Error("Archive loading must not run.");
      },
    },
    device_identity: identityRuntime,
    git_state: {
      async capture(request) {
        calls.push("capture-git");
        assert.equal(request.capturedAt, CAPTURED_AT);
        return git;
      },
      async verify() {
        throw new Error("Git verification must not run.");
      },
    },
    handoff_files: files,
    workspace_store: store,
    clock: { now: () => new Date(CAPTURED_AT) },
    stdout: {
      write(value) {
        stdout.push(value);
      },
    },
    stderr: {
      write(value) {
        stderr.push(value);
      },
    },
  };
  return { dependencies, stdout, stderr, calls, git };
}

function persistenceResult(plan: HandoffStoreWritePlan) {
  return {
    blobs: plan.blobs.map((blob) => ({
      digest: blob.digest,
      byteLength: blob.byteLength,
      relativePath: "blobs/approved",
      disposition: "stored" as const,
    })),
    events: plan.events.map((event) => ({
      eventId: event.eventId,
      eventDigest: event.eventDigest,
      sequence: event.event.sequence,
      disposition: "stored" as const,
    })),
  };
}

function handoffArgs(action: "inspect" | "create", approval?: string) {
  const common = [
    "handoff",
    action,
    "--plan=/private/operator-plan.json",
    "--entire-detail=/private/entire-detail.json",
    `--captured-at=${CAPTURED_AT}`,
  ];
  return action === "create"
    ? [
        ...common,
        `--approve=${approval ?? `sha256:${"0".repeat(64)}`}`,
        "--output=/private/new-archive",
        "--json",
      ]
    : [...common, "--json"];
}

test("handoff inspect returns a bounded review and has no signing or durable effects", async () => {
  const identity = new TestSigningIdentity(
    generateArchiveSigningKey("urn:owc:key:test"),
  );
  const subject = fixture({ identity });
  assert.equal(
    await runCli(handoffArgs("inspect"), subject.dependencies),
    ExitCode.success,
  );
  const serialized = subject.stdout.join("");
  const output = JSON.parse(serialized) as {
    data: {
      review: { approvalDigest: string; included: { artifacts: unknown[] } };
      effects: Record<string, boolean>;
    };
  };
  assert.match(output.data.review.approvalDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(output.data.effects, {
    signed: false,
    persisted: false,
    archive_published: false,
    provider_checkpoint_command_invoked: false,
  });
  assert.deepEqual(subject.calls, [
    "read-plan",
    "read-entire-detail",
    "diagnose-identity",
    "capture-git",
  ]);
  assert.equal(identity.archiveCalls, 0);
  assert.doesNotMatch(
    serialized,
    /DETAIL_TRANSCRIPT|DETAIL_PROMPT|DETAIL_RESPONSE|DETAIL_PRIVATE|PATCH_SECRET|private\/repository/,
  );
});

test("handoff create signs only an exact approval, persists, then publishes", async () => {
  const identity = new TestSigningIdentity(
    generateArchiveSigningKey("urn:owc:key:test"),
  );
  const approval = inspectHandoff({
    entireCheckpointDetailJson: entireDetail,
    plan: plan(),
    capturedAt: CAPTURED_AT,
    git: capturedGit(),
    signingIdentity: identity,
  }).approvalDigest;
  const subject = fixture({ identity });
  assert.equal(
    await runCli(handoffArgs("create", approval), subject.dependencies),
    ExitCode.success,
  );
  const output = JSON.parse(subject.stdout.join("")) as {
    data: {
      approval_digest: string;
      archive: { published: boolean; entry_count: number };
      verification: {
        offline: boolean;
        integrity_valid: boolean;
        signature_valid: boolean;
        approval_recomputed: boolean;
      };
      store: { complete: boolean };
    };
  };
  assert.equal(output.data.approval_digest, approval);
  assert.equal(output.data.archive.published, true);
  assert.ok(output.data.archive.entry_count > 0);
  assert.deepEqual(output.data.verification, {
    offline: true,
    integrity_valid: true,
    signature_valid: true,
    approval_recomputed: true,
  });
  assert.equal(output.data.store.complete, true);
  assert.deepEqual(subject.calls, [
    "preflight-output",
    "read-plan",
    "read-entire-detail",
    "diagnose-identity",
    "capture-git",
    "sign-approved",
    "persist-store",
    "publish-archive",
  ]);
  assert.equal(identity.archiveCalls, 1);
});

test("approval mismatch fails before signing, persistence, or publication", async () => {
  const identity = new TestSigningIdentity(
    generateArchiveSigningKey("urn:owc:key:test"),
  );
  const subject = fixture({ identity });
  assert.equal(
    await runCli(handoffArgs("create"), subject.dependencies),
    ExitCode.notReady,
  );
  assert.equal(identity.archiveCalls, 0);
  assert.equal(subject.calls.includes("sign-approved"), false);
  assert.equal(subject.calls.includes("persist-store"), false);
  assert.equal(subject.calls.includes("publish-archive"), false);
  assert.doesNotMatch(subject.stdout.join(""), /private\/repository/);
});

test("store and publication failures expose honest retry-safe state without details", async (t) => {
  const identity = new TestSigningIdentity(
    generateArchiveSigningKey("urn:owc:key:test"),
  );
  const approval = inspectHandoff({
    entireCheckpointDetailJson: entireDetail,
    plan: plan(),
    capturedAt: CAPTURED_AT,
    git: capturedGit(),
    signingIdentity: identity,
  }).approvalDigest;

  await t.test("partial store", async () => {
    const subject = fixture({ identity, storeFailure: true });
    assert.equal(
      await runCli(handoffArgs("create", approval), subject.dependencies),
      ExitCode.storeInvalid,
    );
    const output = JSON.parse(subject.stdout.join("")) as {
      data: { store: string; archive: string; retry_safe: boolean };
    };
    assert.deepEqual(output.data, {
      store: "partial-or-unknown",
      archive: "not-published",
      retry_safe: true,
    });
    assert.equal(subject.calls.includes("publish-archive"), false);
    assert.doesNotMatch(subject.stdout.join(""), /PRIVATE_STORE_FAILURE/);
  });

  await t.test("publication after complete store", async () => {
    const subject = fixture({
      identity,
      publishFailure: "output_exists",
    });
    assert.equal(
      await runCli(handoffArgs("create", approval), subject.dependencies),
      ExitCode.notReady,
    );
    const output = JSON.parse(subject.stdout.join("")) as {
      data: { store: string; archive: string; retry_safe: boolean };
    };
    assert.deepEqual(output.data, {
      store: "complete",
      archive: "not-published",
      retry_safe: true,
    });
  });
});

test("handoff options are command-scoped and rejected before any I/O", async () => {
  const identity = new TestSigningIdentity(
    generateArchiveSigningKey("urn:owc:key:test"),
  );
  const subject = fixture({ identity });
  assert.equal(
    await runCli(
      [...handoffArgs("inspect"), "--output=/must-not-be-accepted"],
      subject.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(subject.calls.length, 0);
});
