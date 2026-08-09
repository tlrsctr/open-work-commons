import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { ExitCode } from "../../../packages/core/src/index.js";
import type { OperatorHandoffPlan } from "../../../packages/handoff/src/index.js";

import { createDirectoryArchiveLoader } from "./archive-directory.js";
import { runCli, type CliDependencies } from "./cli.js";
import { createDeviceIdentityRuntime } from "./device-identity-runtime.js";
import { createGitStateRuntime } from "./git-state-runtime.js";
import { createHandoffFileRuntime } from "./handoff-file-runtime.js";
import {
  createNodeCommandRunner,
  nodeFileSystemProbe,
} from "./node-runtime.js";
import { createWorkspaceStoreRuntime } from "./store-runtime.js";

const executeFile = promisify(execFile);
const CAPTURED_AT = "2026-08-07T12:00:00Z";
const EXTERNAL_CHECKPOINT_ID = "01KVBJCWYA4YW6J5M9GP655HZN";
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

test(
  "real init, inspect, create, trusted verify, and resume form one offline handoff",
  { timeout: 30_000 },
  async (t) => {
    if (process.platform === "win32") {
      t.skip("The v0 local identity, store, and publisher target POSIX.");
      return;
    }
    const root = await mkdtemp(join(tmpdir(), "owc-handoff-e2e-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const repository = join(root, "repository");
    const inputs = join(root, "inputs");
    const archiveDirectory = join(root, "portable-handoff");
    await mkdir(repository);
    await mkdir(inputs);
    await git(repository, "init");
    await git(repository, "config", "user.email", "owc-test@example.invalid");
    await git(repository, "config", "user.name", "OWC test");
    await writeFile(join(repository, ".gitignore"), ".owc/\n");
    await writeFile(join(repository, "work.txt"), "portable work\n");
    await git(repository, "add", ".gitignore", "work.txt");
    await git(repository, "commit", "-m", "seed exact state");

    const planPath = join(inputs, "operator-plan.json");
    const detailPath = join(inputs, "entire-detail.json");
    await writeFile(planPath, `${JSON.stringify(operatorPlan(), null, 2)}\n`);
    await writeFile(
      detailPath,
      await readFile(
        join(
          repositoryRoot,
          "packages/adapters/entire/test/fixtures/checkpoint-detail.sanitized.json",
        ),
      ),
    );

    const run = cliRunner(repository);
    const initialized = await run(["init", "--json"]);
    assert.equal(initialized.exitCode, ExitCode.success, initialized.stderr);
    const initOutput = JSON.parse(initialized.stdout) as {
      data: { identity: { fingerprint: string } };
    };
    const fingerprint = initOutput.data.identity.fingerprint;

    const common = [
      `--plan=${planPath}`,
      `--entire-detail=${detailPath}`,
      `--captured-at=${CAPTURED_AT}`,
    ];
    const inspected = await run(["handoff", "inspect", ...common, "--json"]);
    assert.equal(
      inspected.exitCode,
      ExitCode.success,
      `${inspected.stderr}\n${inspected.stdout}`,
    );
    const inspectOutput = JSON.parse(inspected.stdout) as {
      data: { review: { approvalDigest: string } };
    };
    const approval = inspectOutput.data.review.approvalDigest;
    assert.match(approval, /^sha256:[a-f0-9]{64}$/);
    assert.doesNotMatch(
      inspected.stdout,
      /DETAIL_TRANSCRIPT|DETAIL_PROMPT|DETAIL_RESPONSE|DETAIL_PRIVATE/,
    );

    const created = await run([
      "handoff",
      "create",
      ...common,
      `--approve=${approval}`,
      `--output=${archiveDirectory}`,
      "--json",
    ]);
    assert.equal(created.exitCode, ExitCode.success, created.stderr);
    const createOutput = JSON.parse(created.stdout) as {
      data: {
        approval_digest: string;
        archive: { published: boolean };
        store: { complete: boolean };
      };
    };
    assert.equal(createOutput.data.approval_digest, approval);
    assert.equal(createOutput.data.archive.published, true);
    assert.equal(createOutput.data.store.complete, true);

    const replayDirectory = join(root, "portable-handoff-replay");
    const replayed = await run([
      "handoff",
      "create",
      ...common,
      `--approve=${approval}`,
      `--output=${replayDirectory}`,
      "--json",
    ]);
    assert.equal(replayed.exitCode, ExitCode.success, replayed.stderr);
    const replayOutput = JSON.parse(replayed.stdout) as {
      data: {
        store: {
          blobs: { stored: number; existing: number };
          events: { stored: number; existing: number };
        };
      };
    };
    assert.equal(replayOutput.data.store.blobs.stored, 0);
    assert.ok(replayOutput.data.store.blobs.existing > 0);
    assert.equal(replayOutput.data.store.events.stored, 0);
    assert.ok(replayOutput.data.store.events.existing > 0);

    const verified = await run([
      "archive",
      "verify",
      archiveDirectory,
      `--trust=${fingerprint}`,
      `--repo=${repository}`,
      "--json",
    ]);
    assert.equal(verified.exitCode, ExitCode.success, verified.stderr);
    const verifyOutput = JSON.parse(verified.stdout) as {
      data: {
        integrity: { valid: boolean };
        signer: { trusted: boolean };
        externalRepositoryVerification: { status: string };
      };
    };
    assert.equal(verifyOutput.data.integrity.valid, true);
    assert.equal(verifyOutput.data.signer.trusted, true);
    assert.equal(
      verifyOutput.data.externalRepositoryVerification.status,
      "matched",
    );

    for (const target of ["codex", "claude"] as const) {
      const resumed = await run([
        "resume",
        "compile",
        archiveDirectory,
        `--target=${target}`,
        "--max-items=64",
        "--max-bytes=65536",
        `--trust=${fingerprint}`,
        "--json",
      ]);
      assert.equal(resumed.exitCode, ExitCode.success, resumed.stderr);
      const resumeOutput = JSON.parse(resumed.stdout) as {
        data: {
          bundle: { target: { provider: string } };
          archive_reverified_offline: boolean;
        };
      };
      assert.equal(resumeOutput.data.bundle.target.provider, target);
      assert.equal(resumeOutput.data.archive_reverified_offline, true);
    }

    const archive = await createDirectoryArchiveLoader().load(archiveDirectory);
    const archivedText = [
      archive.manifestBytes,
      ...archive.entries.map((entry) => entry.bytes),
    ]
      .map((bytes) => Buffer.from(bytes).toString("utf8"))
      .join("\n");
    assert.doesNotMatch(
      archivedText,
      /DETAIL_TRANSCRIPT|DETAIL_PROMPT|DETAIL_RESPONSE|DETAIL_PRIVATE/,
    );
  },
);

function operatorPlan(): OperatorHandoffPlan {
  return {
    source: {
      provider: "entire",
      providerVersion: "0.9.0",
      externalCheckpointId: EXTERNAL_CHECKPOINT_ID,
    },
    actor: { id: "human:e2e", displayName: "E2E operator" },
    spaceId: "space:e2e",
    work: {
      workItemId: "OWC-12",
      title: "Portable handoff proof",
      objective: "Verify one exact cross-agent handoff end to end.",
      constraints: ["Exclude provider transcript content."],
    },
    decisions: ["Approve the exact reviewed archive proposal."],
    openQuestions: ["How useful is the receiving-agent continuation?"],
    nextAction: "Resume this checkpoint with the receiving agent.",
    sensitivity: "private",
    retention: { class: "checkpoint", expiresAt: null },
  };
}

function cliRunner(repository: string) {
  const base: Omit<CliDependencies, "stdout" | "stderr"> = {
    cwd: repository,
    node_version: process.version,
    file_system: nodeFileSystemProbe,
    command_runner: createNodeCommandRunner(),
    archive_loader: createDirectoryArchiveLoader(),
    device_identity: createDeviceIdentityRuntime(repository),
    git_state: createGitStateRuntime(),
    handoff_files: createHandoffFileRuntime(repository),
    workspace_store: createWorkspaceStoreRuntime(),
    clock: { now: () => new Date(CAPTURED_AT) },
  };
  return async (args: readonly string[]) => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const exitCode = await runCli(args, {
      ...base,
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
    });
    return { exitCode, stdout: stdout.join(""), stderr: stderr.join("") };
  };
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await executeFile("git", args, {
    cwd,
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
  });
}
