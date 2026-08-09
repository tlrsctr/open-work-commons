import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { LogicalArchive } from "../../../packages/archive/src/index.js";
import type {
  CommandRequest,
  CommandResult,
} from "../../../packages/core/src/index.js";
import { ExitCode } from "../../../packages/core/src/index.js";
import {
  GitStateCaptureError,
  type CapturedGitState,
} from "../../../packages/git-state/src/index.js";
import {
  DeviceIdentityError,
  type PublicDeviceIdentity,
} from "../../../packages/identity/src/index.js";
import type { ArchiveLoader } from "./archive-directory.js";
import { runCli, type CliDependencies } from "./cli.js";
import type { DeviceIdentityRuntime } from "./device-identity-runtime.js";
import type { GitStateRuntime } from "./git-state-runtime.js";
import type { HandoffFileRuntime } from "./handoff-file-runtime.js";
import type { WorkspaceStoreRuntime } from "./store-runtime.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const fixtureFingerprint =
  "sha256:eff4aaebfeb39519574246101932daf3751a90be679a4bd0caf07bbedf3c8b74";

function fixtureDependencies(
  run: (request: CommandRequest) => Promise<CommandResult>,
  archiveLoader: ArchiveLoader = {
    async load() {
      throw new Error("Archive loader must not run in this test.");
    },
  },
  workspaceStore: WorkspaceStoreRuntime = {
    async initialize() {
      throw new Error("Workspace store must not run in this test.");
    },
    async health() {
      throw new Error("Workspace store must not run in this test.");
    },
  },
  gitState: GitStateRuntime = {
    async capture() {
      throw new Error("Git-state runtime must not run in this test.");
    },
    async verify() {
      throw new Error("Git-state runtime must not run in this test.");
    },
  },
  deviceIdentity: DeviceIdentityRuntime = {
    async openOrCreate() {
      throw new Error("Device identity must not be initialized in this test.");
    },
    async diagnose() {
      throw new Error("Device identity must not be diagnosed in this test.");
    },
  },
  handoffFiles: HandoffFileRuntime = {
    async readPlan() {
      throw new Error("Handoff files must not be read in this test.");
    },
    async readEntireCheckpointDetail() {
      throw new Error("Handoff files must not be read in this test.");
    },
    async assertOutputAvailable() {
      throw new Error("Handoff output must not be inspected in this test.");
    },
    async publishArchive() {
      throw new Error("Handoff archive must not be published in this test.");
    },
  },
) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const accessedPaths: string[] = [];
  const dependencies: CliDependencies = {
    cwd: "/fixture/repository",
    node_version: "v22.14.0",
    file_system: {
      async can_access(path) {
        accessedPaths.push(path);
        return true;
      },
    },
    command_runner: { run },
    archive_loader: archiveLoader,
    device_identity: deviceIdentity,
    git_state: gitState,
    handoff_files: handoffFiles,
    workspace_store: workspaceStore,
    clock: { now: () => new Date("2026-08-07T12:34:56.000Z") },
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
  return { dependencies, stdout, stderr, accessedPaths };
}

function publishedArchive(): LogicalArchive {
  const root = join(repositoryRoot, "conformance/valid/minimal");
  return {
    manifestBytes: readFileSync(join(root, "archive-manifest.json")),
    entries: [
      "checkpoints/checkpoint.json",
      "events/session-started.json",
      "state/git-state.json",
    ].map((path) => ({ path, bytes: readFileSync(join(root, path)) })),
  };
}

function capturedGitState(includeUntracked = false): CapturedGitState {
  const digest = (character: string) =>
    `sha256:${character.repeat(64)}` as `sha256:${string}`;
  const state: CapturedGitState["state"] = {
    schema_version: "0.1",
    repository_id: "urn:owc:repository:test",
    object_format: "sha1",
    captured_at: "2026-08-07T12:34:56.000Z",
    base_commit: "1".repeat(40),
    head_commit: "2".repeat(40),
    head_tree: "3".repeat(40),
    head_ref: "refs/heads/main",
    worktree: {
      clean: false,
      patch: {
        path: "artifacts/git/tracked-changes.owc-git-patch",
        digest: digest("b"),
        byte_length: 18,
      },
      untracked: includeUntracked
        ? [
            {
              path: "notes/pending.txt",
              included: true,
              digest: digest("c"),
              byte_length: 22,
              artifact: {
                path: "artifacts/git/untracked/notes/pending.txt",
                digest: digest("c"),
                byte_length: 22,
              },
            },
          ]
        : [
            {
              path: "notes/pending.txt",
              included: false,
              digest: digest("c"),
              byte_length: 22,
            },
          ],
    },
  };
  const stateBytes = Buffer.from(JSON.stringify(state), "utf8");
  return {
    state,
    stateBytes,
    stateDigest: digest("a"),
    patchArtifact: {
      path: "artifacts/git/tracked-changes.owc-git-patch",
      mediaType: "application/vnd.openworkcommons.git-patch-v1",
      bytes: Buffer.from("PATCH_SECRET_BYTES", "utf8"),
      digest: digest("b"),
      byteLength: 18,
    },
    untrackedArtifacts: includeUntracked
      ? [
          {
            path: "artifacts/git/untracked/notes/pending.txt",
            mediaType: "application/octet-stream",
            bytes: Buffer.from("UNTRACKED_SECRET_BYTES", "utf8"),
            digest: digest("c"),
            byteLength: 22,
          },
        ]
      : [],
  };
}

function publicDeviceIdentity(): PublicDeviceIdentity {
  const publicKey = "pz0lTIwHsq_vqmqFzCxT8Lj6he4QlsyNIPCtNhvBubU";
  const publicSpki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(publicKey, "base64url"),
  ]).toString("base64url");
  return {
    format: "open-work-commons-device-identity",
    schema_version: "0.1",
    algorithm: "ed25519",
    key_id:
      "urn:owc:key:ed25519:eff4aaebfeb39519574246101932daf3751a90be679a4bd0caf07bbedf3c8b74",
    fingerprint: fixtureFingerprint,
    public_key: publicKey,
    public_key_spki: publicSpki,
  };
}

function commandResult(stdout: string, exit_code = 0): CommandResult {
  return { exit_code, stdout, stderr: "" };
}

function entireResult(
  request: CommandRequest,
  statusResult: CommandResult = commandResult(
    JSON.stringify({ enabled: true }),
  ),
): CommandResult {
  const command = request.args.join(" ");
  if (command === "--version") return commandResult("Entire CLI 0.9.0\n");
  if (command === "agent-help --json") {
    return commandResult(
      JSON.stringify({
        subcommands: [
          { name: "status" },
          { name: "agent" },
          { name: "checkpoint" },
        ],
      }),
    );
  }
  if (command === "agent-help status --json") {
    return commandResult(JSON.stringify({ flags: [{ name: "json" }] }));
  }
  if (command === "agent-help agent --json") {
    return commandResult(
      JSON.stringify({
        subcommands: [{ name: "list" }, { name: "add" }, { name: "remove" }],
      }),
    );
  }
  if (command === "agent-help checkpoint --json") {
    return commandResult(
      JSON.stringify({
        subcommands: [{ name: "list" }, { name: "explain" }],
      }),
    );
  }
  if (command === "agent-help checkpoint list --json") {
    return commandResult(
      JSON.stringify({
        flags: [{ name: "json" }, { name: "pending" }, { name: "session" }],
      }),
    );
  }
  if (command === "agent-help checkpoint explain --json") {
    return commandResult(JSON.stringify({ flags: [{ name: "json" }] }));
  }
  if (command === "status --json") return statusResult;
  throw new Error(`Unexpected Entire command: ${command}`);
}

test("provider status JSON mode is stable and uses only the injected subprocess", async () => {
  const requests: CommandRequest[] = [];
  const fixture = fixtureDependencies(async (request) => {
    requests.push(request);
    return entireResult(request);
  });

  const exitCode = await runCli(
    ["provider", "entire", "status", "--json"],
    fixture.dependencies,
  );
  const output = JSON.parse(fixture.stdout.join("")) as {
    command: string;
    exit_code: number;
    data: { state: string };
  };
  assert.equal(exitCode, ExitCode.success);
  assert.equal(output.command, "provider entire status");
  assert.equal(output.exit_code, ExitCode.success);
  assert.equal(output.data.state, "ready");
  assert.equal(fixture.stderr.length, 0);
  assert.ok(requests.every(({ command }) => command === "entire"));
  assert.equal(requests[0]?.args.join(" "), "--version");
  assert.equal(requests.at(-1)?.args.join(" "), "status --json");
});

test("doctor JSON mode uses injected filesystem and subprocess dependencies", async () => {
  const requests: CommandRequest[] = [];
  const fixture = fixtureDependencies(async (request) => {
    requests.push(request);
    if (request.command === "entire") {
      return entireResult(request);
    }
    return { exit_code: 0, stdout: "ok", stderr: "" };
  });

  const exitCode = await runCli(["--json", "doctor"], fixture.dependencies);
  const output = JSON.parse(fixture.stdout.join("")) as {
    command: string;
    ok: boolean;
    data: { checks: Array<{ id: string }> };
  };
  assert.equal(exitCode, ExitCode.success);
  assert.equal(output.command, "doctor");
  assert.equal(output.ok, true);
  assert.deepEqual(fixture.accessedPaths, ["/fixture/repository"]);
  assert.deepEqual(
    requests.slice(0, 2).map(({ command, args }) => [command, args]),
    [
      ["git", ["--version"]],
      ["git", ["rev-parse", "--show-toplevel"]],
    ],
  );
  assert.ok(requests.slice(2).every(({ command }) => command === "entire"));
  assert.deepEqual(
    output.data.checks.map(({ id }) => id),
    [
      "runtime.node",
      "filesystem.cwd",
      "dependency.git",
      "git.repository",
      "provider.entire",
    ],
  );
});

test("disabled Entire and invalid usage return deterministic exit codes", async () => {
  const disabledFixture = fixtureDependencies(async (request) =>
    entireResult(request, commandResult(JSON.stringify({ enabled: false }))),
  );
  assert.equal(
    await runCli(
      ["provider", "entire", "status", "--json"],
      disabledFixture.dependencies,
    ),
    ExitCode.notReady,
  );

  const usageFixture = fixtureDependencies(async () => {
    throw new Error("Subprocess must not run for invalid usage");
  });
  assert.equal(
    await runCli(
      ["provider", "unknown", "status", "--json"],
      usageFixture.dependencies,
    ),
    ExitCode.usage,
  );
  const usage = JSON.parse(usageFixture.stdout.join("")) as {
    error: { code: string };
    exit_code: number;
  };
  assert.deepEqual(usage.error, {
    code: "usage",
    message: "Unknown provider: unknown",
  });
  assert.equal(usage.exit_code, ExitCode.usage);
});

test("provider failures map to stable JSON exit codes", async (t) => {
  const cases = [
    {
      name: "missing executable",
      result: {
        exit_code: null,
        stdout: "",
        stderr: "not retained",
        error_code: "ENOENT" as const,
      },
      expectedState: "unavailable",
      expectedExitCode: ExitCode.dependencyUnavailable,
    },
    {
      name: "failed status command",
      result: { exit_code: 1, stdout: "", stderr: "not retained" },
      expectedState: "error",
      expectedExitCode: ExitCode.providerFailure,
    },
    {
      name: "invalid successful payload",
      result: { exit_code: 0, stdout: "not-json", stderr: "not retained" },
      expectedState: "invalid_output",
      expectedExitCode: ExitCode.invalidProviderOutput,
    },
  ] as const;

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const fixture = fixtureDependencies(async (request) => {
        if (testCase.name === "missing executable") return testCase.result;
        return entireResult(request, testCase.result);
      });
      const exitCode = await runCli(
        ["provider", "entire", "status", "--json"],
        fixture.dependencies,
      );
      const output = JSON.parse(fixture.stdout.join("")) as {
        exit_code: number;
        data: { state: string };
      };
      assert.equal(exitCode, testCase.expectedExitCode);
      assert.equal(output.exit_code, testCase.expectedExitCode);
      assert.equal(output.data.state, testCase.expectedState);
      assert.doesNotMatch(fixture.stdout.join(""), /not retained/);
    });
  }
});

test("usage failures retain explicit JSON output mode", async () => {
  const fixture = fixtureDependencies(async () => {
    throw new Error("Subprocess must not run for invalid usage");
  });
  const exitCode = await runCli(
    ["doctor", "--json", "--json"],
    fixture.dependencies,
  );
  const output = JSON.parse(fixture.stdout.join("")) as {
    exit_code: number;
    error: { code: string };
  };
  assert.equal(exitCode, ExitCode.usage);
  assert.equal(output.exit_code, ExitCode.usage);
  assert.equal(output.error.code, "usage");
  assert.equal(fixture.stderr.length, 0);
});

test("archive verification reports integrity separately from signer trust", async () => {
  const archive = publishedArchive();
  const loader: ArchiveLoader = {
    async load() {
      return archive;
    },
  };
  const fixture = fixtureDependencies(async () => {
    throw new Error("Subprocess must not run for archive verification");
  }, loader);

  const exitCode = await runCli(
    [
      "archive",
      "verify",
      "/fixture/archive",
      "--allow-untrusted-signer",
      "--json",
    ],
    fixture.dependencies,
  );
  const output = JSON.parse(fixture.stdout.join("")) as {
    exit_code: number;
    data: {
      integrity: { valid: boolean };
      signer: { signatureValid: boolean; trust: string; trusted: boolean };
      operator_policy: { integrity_only_acknowledged: boolean };
    };
  };
  assert.equal(exitCode, ExitCode.success);
  assert.equal(output.data.integrity.valid, true);
  assert.equal(output.data.signer.signatureValid, true);
  assert.equal(output.data.signer.trust, "not-configured");
  assert.equal(output.data.signer.trusted, false);
  assert.equal(output.data.operator_policy.integrity_only_acknowledged, true);

  const trustedFixture = fixtureDependencies(async () => {
    throw new Error("Subprocess must not run for archive verification");
  }, loader);
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        `--trust=${fixtureFingerprint}`,
        "--json",
      ],
      trustedFixture.dependencies,
    ),
    ExitCode.success,
  );
  const trustedOutput = JSON.parse(trustedFixture.stdout.join("")) as {
    data: {
      signer: { trust: string; trusted: boolean };
      operator_policy: { integrity_only_acknowledged: boolean };
    };
  };
  assert.equal(trustedOutput.data.signer.trust, "trusted");
  assert.equal(trustedOutput.data.signer.trusted, true);
  assert.equal(
    trustedOutput.data.operator_policy.integrity_only_acknowledged,
    false,
  );
});

test("archive verification can match one requested local repository", async () => {
  const requests: Parameters<GitStateRuntime["verify"]>[0][] = [];
  const fixture = fixtureDependencies(
    async () => {
      throw new Error(
        "Generic subprocess must not run for archive verification",
      );
    },
    {
      async load() {
        return publishedArchive();
      },
    },
    undefined,
    {
      async capture() {
        throw new Error("Git capture must not run for archive verification");
      },
      async verify(request) {
        requests.push(request);
        return { status: "matched", reason: "exact_git_state_match" };
      },
    },
  );

  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        "--repo=.",
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.success,
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0]?.cwd, ".");
  assert.equal(
    requests[0]?.declaredState.repository_id,
    "urn:owc:repository:fixture-open-work-commons",
  );
  const serialized = fixture.stdout.join("");
  const output = JSON.parse(serialized) as {
    data: {
      integrity: { valid: boolean };
      externalRepositoryVerification: { status: string; reason: string };
    };
  };
  assert.equal(output.data.integrity.valid, true);
  assert.deepEqual(output.data.externalRepositoryVerification, {
    status: "matched",
    reason: "exact_git_state_match",
  });
  assert.doesNotMatch(serialized, /\/fixture\/archive/);
});

test("requested repository mismatch and unavailability return fixed nonzero results", async (t) => {
  const cases = [
    {
      result: {
        status: "mismatched" as const,
        reason: "tracked_patch_mismatch" as const,
      },
    },
    {
      result: {
        status: "unavailable" as const,
        reason: "repository_unavailable" as const,
      },
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.result.status, async () => {
      const fixture = fixtureDependencies(
        async () => {
          throw new Error("No generic subprocess expected");
        },
        {
          async load() {
            return publishedArchive();
          },
        },
        undefined,
        {
          async capture() {
            throw new Error("Capture must not run");
          },
          async verify() {
            return testCase.result;
          },
        },
      );
      assert.equal(
        await runCli(
          [
            "archive",
            "verify",
            "/private/archive",
            "--repo=/Users/example/private/repository",
            "--allow-untrusted-signer",
            "--json",
          ],
          fixture.dependencies,
        ),
        ExitCode.notReady,
      );
      const serialized = fixture.stdout.join("");
      const output = JSON.parse(serialized) as {
        ok: boolean;
        exit_code: number;
        data: {
          integrity: { valid: boolean };
          externalRepositoryVerification: {
            status: string;
            reason: string;
          };
        };
      };
      assert.equal(output.ok, false);
      assert.equal(output.exit_code, ExitCode.notReady);
      assert.equal(output.data.integrity.valid, true);
      assert.deepEqual(
        output.data.externalRepositoryVerification,
        testCase.result,
      );
      assert.doesNotMatch(serialized, /Users\/example|private\/repository/);
    });
  }
});

test("a signer policy mismatch prevents local repository inspection", async () => {
  let repositoryInspections = 0;
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    {
      async load() {
        return publishedArchive();
      },
    },
    undefined,
    {
      async capture() {
        throw new Error("Capture must not run");
      },
      async verify() {
        repositoryInspections += 1;
        return {
          status: "mismatched",
          reason: "git_state_mismatch",
        };
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        "--repo=.",
        `--trust=sha256:${"0".repeat(64)}`,
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.signerUntrusted,
  );
  assert.equal(repositoryInspections, 0);
  const output = JSON.parse(fixture.stdout.join("")) as {
    data: { externalRepositoryVerification: { status: string } };
  };
  assert.equal(
    output.data.externalRepositoryVerification.status,
    "not-checked",
  );
});

test("an invalid archive never drives local repository inspection", async () => {
  const archive = publishedArchive();
  const tampered: LogicalArchive = {
    manifestBytes: archive.manifestBytes,
    entries: archive.entries.map((entry, index) => ({
      ...entry,
      bytes:
        index === 0
          ? Buffer.from("INVALID_ARCHIVE_CONTENT", "utf8")
          : entry.bytes,
    })),
  };
  let repositoryInspections = 0;
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    {
      async load() {
        return tampered;
      },
    },
    undefined,
    {
      async capture() {
        throw new Error("Capture must not run");
      },
      async verify() {
        repositoryInspections += 1;
        return { status: "matched", reason: "exact_git_state_match" };
      },
    },
  );

  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        "--repo=.",
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.archiveInvalid,
  );
  assert.equal(repositoryInspections, 0);
  const output = JSON.parse(fixture.stdout.join("")) as {
    data: { externalRepositoryVerification: { status: string } };
  };
  assert.deepEqual(output.data.externalRepositoryVerification, {
    status: "not-checked",
  });
});

test("archive verification fails deterministically for tampering and trust mismatch", async () => {
  const archive = publishedArchive();
  const tampered: LogicalArchive = {
    manifestBytes: archive.manifestBytes,
    entries: archive.entries.map((entry, index) => ({
      ...entry,
      bytes:
        index === 0
          ? new TextEncoder().encode("HOSTILE_PAYLOAD_MUST_NOT_LEAK")
          : entry.bytes,
    })),
  };
  const tamperedFixture = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for archive verification");
    },
    {
      async load() {
        return tampered;
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        "--allow-untrusted-signer",
        "--json",
      ],
      tamperedFixture.dependencies,
    ),
    ExitCode.archiveInvalid,
  );
  assert.doesNotMatch(
    tamperedFixture.stdout.join(""),
    /HOSTILE_PAYLOAD_MUST_NOT_LEAK/,
  );

  const mismatchFixture = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for archive verification");
    },
    {
      async load() {
        return archive;
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        `--trust=sha256:${"0".repeat(64)}`,
        "--json",
      ],
      mismatchFixture.dependencies,
    ),
    ExitCode.signerUntrusted,
  );
});

test("archive load and trust-option errors expose no local path details", async () => {
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for archive verification");
    },
    {
      async load() {
        throw new Error("private path /Users/example/secret");
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/private/archive",
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.archiveInvalid,
  );
  assert.doesNotMatch(fixture.stdout.join(""), /Users\/example|private path/);

  const usageFixture = fixtureDependencies(async () => {
    throw new Error("No subprocess expected");
  });
  assert.equal(
    await runCli(
      ["archive", "verify", "/fixture", "--trust=not-a-fingerprint", "--json"],
      usageFixture.dependencies,
    ),
    ExitCode.usage,
  );
});

test("archive verification requires one explicit signer policy before loading", async () => {
  let loads = 0;
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    {
      async load() {
        loads += 1;
        return publishedArchive();
      },
    },
  );

  assert.equal(
    await runCli(
      ["archive", "verify", "/fixture/archive", "--json"],
      fixture.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        `--trust=${fixtureFingerprint}`,
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      [
        "archive",
        "verify",
        "/fixture/archive",
        "--allow-untrusted-signer",
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(loads, 0);
});

test("git snapshot reports exact state and artifact metadata without emitting captured bytes", async () => {
  const requests: Array<{
    cwd: string;
    capturedAt: string;
    repositoryId?: string;
    includeUntracked: boolean;
  }> = [];
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("Generic subprocess runner must not run for Git capture");
    },
    undefined,
    undefined,
    {
      async capture(request) {
        requests.push(request);
        return capturedGitState(false);
      },
      async verify() {
        throw new Error("Git verification must not run for snapshot.");
      },
    },
  );

  assert.equal(
    await runCli(["git", "snapshot", "--json"], fixture.dependencies),
    ExitCode.success,
  );
  assert.deepEqual(requests, [
    {
      cwd: "/fixture/repository",
      capturedAt: "2026-08-07T12:34:56.000Z",
      includeUntracked: false,
    },
  ]);
  const serialized = fixture.stdout.join("");
  const output = JSON.parse(serialized) as {
    command: string;
    data: {
      state: { repository_id: string };
      state_serialization: { digest: string; byte_length: number };
      artifacts: {
        tracked_patch: { path: string; digest: string; byte_length: number };
        untracked: unknown[];
      };
      capture_policy: {
        untracked: string;
        artifact_bytes_emitted: boolean;
        archive_created: boolean;
      };
    };
  };
  assert.equal(output.command, "git snapshot");
  assert.equal(output.data.state.repository_id, "urn:owc:repository:test");
  assert.equal(
    output.data.state_serialization.digest,
    `sha256:${"a".repeat(64)}`,
  );
  assert.equal(
    output.data.artifacts.tracked_patch.path,
    "artifacts/git/tracked-changes.owc-git-patch",
  );
  assert.equal(output.data.artifacts.tracked_patch.byte_length, 18);
  assert.deepEqual(output.data.artifacts.untracked, []);
  assert.deepEqual(output.data.capture_policy, {
    untracked: "manifest-only",
    artifact_bytes_emitted: false,
    archive_created: false,
  });
  assert.doesNotMatch(serialized, /PATCH_SECRET_BYTES|UNTRACKED_SECRET_BYTES/);
});

test("git snapshot scopes explicit capture options and states its non-persistence boundary", async () => {
  const requests: Parameters<GitStateRuntime["capture"]>[0][] = [];
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    undefined,
    undefined,
    {
      async capture(request) {
        requests.push(request);
        return capturedGitState(true);
      },
      async verify() {
        throw new Error("Git verification must not run for snapshot.");
      },
    },
  );
  fixture.dependencies.clock.now = () => {
    throw new Error("Clock must not run when --captured-at is supplied");
  };

  assert.equal(
    await runCli(
      [
        "git",
        "snapshot",
        "--captured-at=2026-08-07T10:00:00+02:00",
        "--repository-id=urn:example:repository:one",
        "--include-untracked",
      ],
      fixture.dependencies,
    ),
    ExitCode.success,
  );
  assert.deepEqual(requests, [
    {
      cwd: "/fixture/repository",
      capturedAt: "2026-08-07T10:00:00+02:00",
      repositoryId: "urn:example:repository:one",
      includeUntracked: true,
    },
  ]);
  assert.match(
    fixture.stdout.join(""),
    /Artifact bytes were not emitted, and no archive was created\./,
  );
  assert.doesNotMatch(
    fixture.stdout.join(""),
    /PATCH_SECRET_BYTES|UNTRACKED_SECRET_BYTES/,
  );
});

test("git snapshot text names the manifest-only untracked policy accurately", async () => {
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    undefined,
    undefined,
    {
      async capture() {
        return capturedGitState(false);
      },
      async verify() {
        throw new Error("Git verification must not run for snapshot.");
      },
    },
  );
  assert.equal(
    await runCli(["git", "snapshot"], fixture.dependencies),
    ExitCode.success,
  );
  assert.match(
    fixture.stdout.join(""),
    /Untracked: 1 manifest entries; 0 content artifacts captured \(manifest-only policy\)\./,
  );
  assert.doesNotMatch(fixture.stdout.join(""), /content artifacts included/);
});

test("git snapshot rejects foreign or invalid flags before capture and maps fixed failures", async () => {
  let calls = 0;
  const invalid = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    undefined,
    undefined,
    {
      async capture() {
        calls += 1;
        return capturedGitState();
      },
      async verify() {
        throw new Error("Git verification must not run for snapshot.");
      },
    },
  );
  assert.equal(
    await runCli(
      ["git", "snapshot", "--captured-at=2026-02-30T00:00:00Z", "--json"],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      ["git", "snapshot", `--trust=${fixtureFingerprint}`, "--json"],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      ["git", "snapshot", "--include-untracked", "--include-untracked"],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(calls, 0);

  const failed = fixtureDependencies(
    async () => {
      throw new Error("No generic subprocess expected");
    },
    undefined,
    undefined,
    {
      async capture() {
        throw new GitStateCaptureError(
          "NOT_A_GIT_WORKTREE",
          "private /Users/example/secret must not leak",
        );
      },
      async verify() {
        throw new Error("Git verification must not run for snapshot.");
      },
    },
  );
  assert.equal(
    await runCli(["git", "snapshot", "--json"], failed.dependencies),
    ExitCode.notReady,
  );
  assert.doesNotMatch(failed.stdout.join(""), /Users\/example|secret/);
});

test("resume compile re-verifies the archive and emits stable bundle metadata in JSON mode", async () => {
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for resume compilation");
    },
    {
      async load() {
        return publishedArchive();
      },
    },
  );

  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/private/archive",
        "--target=claude",
        "--max-items=64",
        "--max-bytes=32768",
        `--trust=${fixtureFingerprint}`,
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.success,
  );
  const serialized = fixture.stdout.join("");
  const output = JSON.parse(serialized) as {
    command: string;
    data: {
      bundle: {
        target: { provider: string };
        budget: { actual_utf8_bytes: number; max_utf8_bytes: number };
      };
      serialization: {
        bundle_json: { digest: string; byte_length: number };
        markdown: { digest: string; byte_length: number };
      };
      archive_reverified_offline: boolean;
      signer: {
        trust: string;
        fingerprint: string;
        integrity_only_acknowledged: boolean;
      };
    };
  };
  assert.equal(output.command, "resume compile");
  assert.equal(output.data.bundle.target.provider, "claude");
  assert.equal(output.data.archive_reverified_offline, true);
  assert.deepEqual(output.data.signer, {
    trust: "trusted",
    fingerprint: fixtureFingerprint,
    integrity_only_acknowledged: false,
  });
  assert.equal(
    output.data.serialization.bundle_json.digest,
    "sha256:b8b3df7574d27750eb8f8d55a5f2eeadc535323ebadbfe7eed5ac8b8cddf2fb3",
  );
  assert.equal(
    output.data.serialization.markdown.digest,
    "sha256:889767e9a060cd185cb0f0e5921daec71c0a3b9f3736dda38cb8765a6e1c8b53",
  );
  assert.equal(
    Math.max(
      output.data.serialization.bundle_json.byte_length,
      output.data.serialization.markdown.byte_length,
    ),
    output.data.bundle.budget.actual_utf8_bytes,
  );
  assert.ok(
    output.data.serialization.markdown.byte_length <=
      output.data.bundle.budget.max_utf8_bytes,
  );
  assert.doesNotMatch(serialized, /\/fixture\/private\/archive/);
  assert.doesNotMatch(serialized, /# Open Work Commons resume bundle/);
});

test("resume compile text mode prints only bounded Markdown", async () => {
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for resume compilation");
    },
    {
      async load() {
        return publishedArchive();
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        "--allow-untrusted-signer",
      ],
      fixture.dependencies,
    ),
    ExitCode.success,
  );
  const markdown = fixture.stdout.join("");
  assert.match(markdown, /^# Open Work Commons resume bundle for Codex\n/);
  assert.match(markdown, /<<<OWC_UNTRUSTED_CONTENT:END>>>\n$/);
  assert.ok(Buffer.byteLength(markdown, "utf8") <= 32_768);
  assert.equal(fixture.stderr.length, 0);
});

test("resume JSON records an explicit integrity-only signer acknowledgement", async () => {
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    {
      async load() {
        return publishedArchive();
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        "--allow-untrusted-signer",
        "--json",
      ],
      fixture.dependencies,
    ),
    ExitCode.success,
  );
  const output = JSON.parse(fixture.stdout.join("")) as {
    data: {
      signer: {
        trust: string;
        fingerprint: string;
        integrity_only_acknowledged: boolean;
      };
    };
  };
  assert.deepEqual(output.data.signer, {
    trust: "not-configured",
    fingerprint: fixtureFingerprint,
    integrity_only_acknowledged: true,
  });
});

test("resume compile fails closed with fixed diagnostics and command-scoped options", async () => {
  const mismatch = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    {
      async load() {
        return publishedArchive();
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        `--trust=sha256:${"0".repeat(64)}`,
        "--json",
      ],
      mismatch.dependencies,
    ),
    ExitCode.signerUntrusted,
  );

  const loadFailure = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    {
      async load() {
        throw new Error("private /Users/example/resume archive");
      },
    },
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/private/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        "--allow-untrusted-signer",
        "--json",
      ],
      loadFailure.dependencies,
    ),
    ExitCode.archiveInvalid,
  );
  assert.doesNotMatch(
    loadFailure.stdout.join(""),
    /Users\/example|private \/|resume archive/,
  );

  const invalid = fixtureDependencies(async () => {
    throw new Error("No subprocess expected");
  });
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        "--json",
      ],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        `--trust=${fixtureFingerprint}`,
        "--allow-untrusted-signer",
        "--json",
      ],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=0",
        "--max-bytes=32768",
        "--json",
      ],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
  assert.equal(
    await runCli(
      [
        "resume",
        "compile",
        "/fixture/archive",
        "--target=codex",
        "--max-items=64",
        "--max-bytes=32768",
        "--include-untracked",
        "--json",
      ],
      invalid.dependencies,
    ),
    ExitCode.usage,
  );
});

test("strict-local checkpoint discovery exposes the provider fetch boundary", async () => {
  const requests: CommandRequest[] = [];
  const fixture = fixtureDependencies(async (request) => {
    requests.push(request);
    return entireResult(request);
  });

  const exitCode = await runCli(
    ["provider", "entire", "checkpoints", "--json"],
    fixture.dependencies,
  );
  const output = JSON.parse(fixture.stdout.join("")) as {
    exit_code: number;
    data: { status: string; reason: string };
  };
  assert.equal(exitCode, ExitCode.notReady);
  assert.equal(output.exit_code, ExitCode.notReady);
  assert.equal(output.data.status, "unavailable");
  assert.equal(
    output.data.reason,
    "provider_cli_may_fetch_remote_checkpoint_data",
  );
  assert.equal(
    requests.some(({ args }) => args[0] === "checkpoint"),
    false,
  );
});

test("initialization opens the store before one public-only device identity", async () => {
  const order: string[] = [];
  const store: WorkspaceStoreRuntime = {
    async initialize() {
      order.push("store");
      return { store_path: "/fixture/repository/.owc" };
    },
    async health() {
      return { ok: true, checkedEvents: 2, checkedBlobs: 1, issues: [] };
    },
  };
  const initialized = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for store commands");
    },
    undefined,
    store,
    undefined,
    {
      async openOrCreate(privateDirectory) {
        order.push(`identity:${privateDirectory}`);
        return publicDeviceIdentity();
      },
      async diagnose() {
        throw new Error("Identity diagnose must not run during init");
      },
    },
  );
  assert.equal(
    await runCli(["init", "--json"], initialized.dependencies),
    ExitCode.success,
  );
  const serialized = initialized.stdout.join("");
  const initOutput = JSON.parse(serialized) as {
    data: {
      workspace_store: { initialized: boolean; content_policy: string };
      identity: { fingerprint: string; public_key: string };
    };
  };
  assert.deepEqual(order, ["store", "identity:/fixture/repository/.owc"]);
  assert.deepEqual(initOutput.data.workspace_store, {
    initialized: true,
    content_policy: "deny-until-configured",
  });
  assert.equal(initOutput.data.identity.fingerprint, fixtureFingerprint);
  assert.equal(
    initOutput.data.identity.public_key,
    publicDeviceIdentity().public_key,
  );
  assert.doesNotMatch(serialized, /\/fixture\/repository|private-key|pk8/);

  const healthy = fixtureDependencies(
    async () => {
      throw new Error("Subprocess must not run for store commands");
    },
    undefined,
    store,
  );
  assert.equal(
    await runCli(["store", "health", "--json"], healthy.dependencies),
    ExitCode.success,
  );
  const healthOutput = JSON.parse(healthy.stdout.join("")) as {
    data: { ok: boolean; checkedEvents: number; checkedBlobs: number };
  };
  assert.deepEqual(healthOutput.data, {
    ok: true,
    checkedEvents: 2,
    checkedBlobs: 1,
    issues: [],
  });
});

test("identity status diagnoses without creating and strips undeclared fields", async () => {
  let openOrCreateCalls = 0;
  let diagnoseCalls = 0;
  const identity = publicDeviceIdentity();
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    undefined,
    undefined,
    {
      async openOrCreate() {
        openOrCreateCalls += 1;
        return identity;
      },
      async diagnose() {
        diagnoseCalls += 1;
        return {
          ok: true,
          code: "ready",
          identity: {
            ...identity,
            private_key: "PRIVATE_KEY_CANARY",
            local_path: "/Users/example/private/device",
          } as PublicDeviceIdentity,
          message: "The local device identity is ready.",
        };
      },
    },
  );

  assert.equal(
    await runCli(["identity", "status", "--json"], fixture.dependencies),
    ExitCode.success,
  );
  assert.equal(openOrCreateCalls, 0);
  assert.equal(diagnoseCalls, 1);
  const serialized = fixture.stdout.join("");
  const output = JSON.parse(serialized) as {
    data: { state: string; identity: Record<string, unknown> };
  };
  assert.equal(output.data.state, "ready");
  assert.equal(output.data.identity.fingerprint, fixtureFingerprint);
  assert.deepEqual(Object.keys(output.data.identity).sort(), [
    "algorithm",
    "fingerprint",
    "format",
    "key_id",
    "public_key",
    "public_key_spki",
    "schema_version",
  ]);
  assert.doesNotMatch(
    serialized,
    /PRIVATE_KEY_CANARY|Users\/example|local_path/,
  );
});

test("identity status maps fixed safe diagnostics without echoing runtime messages", async () => {
  const missing = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    undefined,
    undefined,
    {
      async openOrCreate() {
        throw new Error("openOrCreate must not run for status");
      },
      async diagnose() {
        return {
          ok: false,
          code: "not_found",
          identity: null,
          message: "private /Users/example/device must not leak",
        };
      },
    },
  );
  assert.equal(
    await runCli(["identity", "status", "--json"], missing.dependencies),
    ExitCode.notReady,
  );
  const missingOutput = JSON.parse(missing.stdout.join("")) as {
    error: { code: string; message: string };
  };
  assert.deepEqual(missingOutput.error, {
    code: "identity_not_found",
    message: "The local device identity is not initialized.",
  });
  assert.doesNotMatch(
    missing.stdout.join(""),
    /Users\/example|private \/|must not leak/,
  );

  const unexpected = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    undefined,
    undefined,
    {
      async openOrCreate() {
        throw new Error("openOrCreate must not run for status");
      },
      async diagnose() {
        throw new Error("OS error at /Users/example/private-key.pk8");
      },
    },
  );
  assert.equal(
    await runCli(["identity", "status", "--json"], unexpected.dependencies),
    ExitCode.storeInvalid,
  );
  assert.doesNotMatch(
    unexpected.stdout.join(""),
    /Users\/example|private-key|OS error/,
  );
});

test("identity failure after store initialization reports retry-safe partial state", async () => {
  const calls: string[] = [];
  const fixture = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    {
      async initialize() {
        calls.push("store");
        return { store_path: "/private/workspace/.owc" };
      },
      async health() {
        throw new Error("health must not run");
      },
    },
    undefined,
    {
      async openOrCreate(privateDirectory) {
        calls.push(`identity:${privateDirectory}`);
        throw new DeviceIdentityError("unsafe_permissions");
      },
      async diagnose() {
        throw new Error("diagnose must not run during init");
      },
    },
  );
  assert.equal(
    await runCli(["init", "--json"], fixture.dependencies),
    ExitCode.storeInvalid,
  );
  assert.deepEqual(calls, ["store", "identity:/private/workspace/.owc"]);
  const serialized = fixture.stdout.join("");
  const output = JSON.parse(serialized) as {
    error: { code: string; message: string };
    data: {
      workspace_store_initialized: boolean;
      identity_ready: boolean;
      init_retry_safe: boolean;
    };
  };
  assert.deepEqual(output.error, {
    code: "identity_unsafe_permissions",
    message: "The local device identity failed its storage safety checks.",
  });
  assert.deepEqual(output.data, {
    workspace_store_initialized: true,
    identity_ready: false,
    init_retry_safe: true,
  });
  assert.doesNotMatch(serialized, /private\/workspace|\.owc/);
});

test("store errors use fixed diagnostics without leaking implementation detail", async () => {
  const failingStore: WorkspaceStoreRuntime = {
    async initialize() {
      throw new Error("secret filesystem detail");
    },
    async health() {
      return {
        ok: false,
        checkedEvents: 0,
        checkedBlobs: 0,
        issues: [
          {
            code: "workspace_layout_invalid",
            location: "store-root",
            message: "A required private store directory is invalid.",
          },
        ],
      };
    },
  };
  const init = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    failingStore,
  );
  assert.equal(
    await runCli(["init", "--json"], init.dependencies),
    ExitCode.storeInvalid,
  );
  assert.doesNotMatch(init.stdout.join(""), /secret filesystem detail/);

  const health = fixtureDependencies(
    async () => {
      throw new Error("No subprocess expected");
    },
    undefined,
    failingStore,
  );
  assert.equal(
    await runCli(["store", "health", "--json"], health.dependencies),
    ExitCode.storeInvalid,
  );
});
