import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { compileLocalSchemas } from "../../../conformance/harness/src/harness.js";

import { captureGitState } from "./capture.js";
import { createNodeGitCommandRunner } from "./node-runner.js";
import { decodeGitPatchArtifact } from "./patch-format.js";
import { GitStateCaptureError, type GitCommandRunner } from "./types.js";

const CAPTURED_AT = "2026-08-07T12:00:00Z";
const runner = createNodeGitCommandRunner();

test("captures a clean repository without requiring a remote", async (t) => {
  const repository = await createRepository(t);
  const captured = await capture(repository);

  assert.equal(captured.state.schema_version, "0.1");
  assert.equal(captured.state.base_commit, captured.state.head_commit);
  assert.match(captured.state.repository_id, /^urn:owc:repository:git:sha1:/);
  assert.equal(captured.state.head_ref, "refs/heads/main");
  assert.equal(captured.state.worktree.clean, true);
  assert.deepEqual(captured.state.worktree.untracked, []);
  assert.equal(captured.patchArtifact, null);
  assert.deepEqual(captured.untrackedArtifacts, []);
  assert.match(captured.stateDigest, /^sha256:[a-f0-9]{64}$/);
});

test("emits a state object accepted by the independent v0 schema oracle", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "schema-bound change\n");
  await writeFile(join(repository, "new.txt"), "schema-bound untracked\n");
  const captured = await capture(repository);
  const schemas = await compileLocalSchemas();

  assert.deepEqual(schemas.validate("gitState", captured.state), {
    valid: true,
    errors: [],
  });
  const included = await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
    untrackedPolicy: "include",
  });
  assert.deepEqual(schemas.validate("gitState", included.state), {
    valid: true,
    errors: [],
  });
});

test("captures staged binary changes in the index section", async (t) => {
  const repository = await createRepository(t, Buffer.from([0, 1, 2, 3]));
  await writeFile(join(repository, "tracked.bin"), Buffer.from([0, 9, 8, 7]));
  git(repository, "add", "tracked.bin");

  const captured = await capture(repository);
  assert.equal(captured.state.worktree.clean, false);
  assert.ok(captured.patchArtifact);
  const sections = decodeGitPatchArtifact(captured.patchArtifact.bytes);
  assert.ok(sections.index.byteLength > 0);
  assert.equal(sections.worktree.byteLength, 0);
  assert.match(
    Buffer.from(sections.index).toString("ascii"),
    /GIT binary patch/,
  );
  assert.equal(
    captured.state.worktree.patch?.digest,
    captured.patchArtifact.digest,
  );
  assert.equal(
    captured.patchArtifact.mediaType,
    "application/vnd.openworkcommons.git-patch-v1",
  );
});

test("captures unstaged tracked changes in the worktree section", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "worktree version\n");

  const captured = await capture(repository);
  assert.ok(captured.patchArtifact);
  const sections = decodeGitPatchArtifact(captured.patchArtifact.bytes);
  assert.equal(sections.index.byteLength, 0);
  assert.ok(sections.worktree.byteLength > 0);
  assert.match(
    Buffer.from(sections.worktree).toString("utf8"),
    /\+worktree version/,
  );
});

test("sorts untracked files, hashes them, and never captures ignored files", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, ".gitignore"), "ignored-secret.txt\n");
  git(repository, "add", ".gitignore");
  git(repository, "commit", "-m", "add ignore policy");
  await writeFile(join(repository, "z.txt"), "zeta\n");
  await writeFile(join(repository, "a.txt"), "alpha\n");
  await writeFile(join(repository, "ignored-secret.txt"), "secret canary\n");

  const manifestOnly = await capture(repository);
  assert.deepEqual(
    manifestOnly.state.worktree.untracked.map((entry) => entry.path),
    ["a.txt", "z.txt"],
  );
  assert.ok(
    manifestOnly.state.worktree.untracked.every(
      (entry) =>
        entry.included === false &&
        !("artifact" in entry) &&
        entry.digest.startsWith("sha256:") &&
        entry.byte_length > 0,
    ),
  );
  assert.deepEqual(manifestOnly.untrackedArtifacts, []);
  assert.doesNotMatch(
    Buffer.from(manifestOnly.stateBytes).toString("utf8"),
    /ignored-secret/,
  );

  const included = await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
    untrackedPolicy: "include",
  });
  assert.ok(included.state.worktree.untracked.every((entry) => entry.included));
  assert.deepEqual(
    included.state.worktree.untracked.map((entry) => ({
      repositoryPath: entry.path,
      artifactPath: entry.artifact?.path,
      digestMatches: entry.digest === entry.artifact?.digest,
      lengthMatches: entry.byte_length === entry.artifact?.byte_length,
    })),
    [
      {
        repositoryPath: "a.txt",
        artifactPath: "artifacts/git/untracked/a.txt",
        digestMatches: true,
        lengthMatches: true,
      },
      {
        repositoryPath: "z.txt",
        artifactPath: "artifacts/git/untracked/z.txt",
        digestMatches: true,
        lengthMatches: true,
      },
    ],
  );
  assert.deepEqual(
    included.untrackedArtifacts.map((artifact) => artifact.path),
    ["artifacts/git/untracked/a.txt", "artifacts/git/untracked/z.txt"],
  );
  assert.doesNotMatch(
    JSON.stringify(included.untrackedArtifacts.map((entry) => entry.path)),
    /ignored-secret/,
  );
});

test("reports null symbolic head for detached HEAD", async (t) => {
  const repository = await createRepository(t);
  git(repository, "checkout", "--detach", "HEAD");

  const captured = await capture(repository);
  assert.equal(captured.state.head_ref, null);
});

test("fails closed outside a Git worktree", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "owc-git-state-outside-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  await assert.rejects(
    capture(directory),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "NOT_A_GIT_WORKTREE",
  );
});

test("reports a subprocess failure when Git cannot be started", async (t) => {
  const repository = await createRepository(t);
  const missingGit = createNodeGitCommandRunner({
    gitExecutable: "owc-definitely-missing-git-executable",
  });

  await assert.rejects(
    captureGitState({
      cwd: repository,
      capturedAt: CAPTURED_AT,
      runner: missingGit,
    }),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "SUBPROCESS_ERROR",
  );
});

test("produces identical bytes for identical repeated observations", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "repeatable change\n");
  await writeFile(join(repository, "new.txt"), "repeatable untracked\n");

  const first = await capture(repository);
  const second = await capture(repository);
  assert.deepEqual(first.stateBytes, second.stateBytes);
  assert.equal(first.stateDigest, second.stateDigest);
  assert.deepEqual(first.patchArtifact?.bytes, second.patchArtifact?.bytes);
  assert.equal(first.patchArtifact?.digest, second.patchArtifact?.digest);
});

test("binds tracked and untracked tampering to different digests", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "tracked two\n");
  await writeFile(join(repository, "new.txt"), "untracked A\n");
  const first = await capture(repository);

  await writeFile(join(repository, "tracked.txt"), "tracked six\n");
  await writeFile(join(repository, "new.txt"), "untracked B\n");
  const second = await capture(repository);

  assert.notEqual(first.patchArtifact?.digest, second.patchArtifact?.digest);
  assert.notEqual(
    first.state.worktree.untracked[0]?.digest,
    second.state.worktree.untracked[0]?.digest,
  );
  assert.notEqual(first.stateDigest, second.stateDigest);
});

test("rejects untracked paths outside the v0 safe path profile", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "unsafe name.txt"), "unsafe\n");

  await assert.rejects(
    capture(repository),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "UNSAFE_UNTRACKED_PATH",
  );
});

test("enforces patch output limits", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "a much larger change\n");

  await assert.rejects(
    captureGitState({
      cwd: repository,
      capturedAt: CAPTURED_AT,
      runner,
      limits: { patchSectionBytes: 8 },
    }),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "OUTPUT_LIMIT_EXCEEDED",
  );
});

test("resolves an explicit ancestor base and rejects a non-ancestor", async (t) => {
  const repository = await createRepository(t);
  const base = git(repository, "rev-parse", "HEAD").trim();
  await writeFile(join(repository, "tracked.txt"), "second commit\n");
  git(repository, "add", "tracked.txt");
  git(repository, "commit", "-m", "second");
  const head = git(repository, "rev-parse", "HEAD").trim();

  const captured = await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
    baseRevision: base,
  });
  assert.equal(captured.state.base_commit, base);
  assert.equal(captured.state.head_commit, head);

  git(repository, "checkout", "--orphan", "unrelated");
  git(repository, "rm", "-rf", ".");
  await writeFile(join(repository, "orphan.txt"), "orphan\n");
  git(repository, "add", "orphan.txt");
  git(repository, "commit", "-m", "orphan");

  await assert.rejects(
    captureGitState({
      cwd: repository,
      capturedAt: CAPTURED_AT,
      runner,
      baseRevision: base,
    }),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "BASE_NOT_ANCESTOR",
  );
});

test("captures SHA-256 repositories with 64-character object identifiers", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "owc-git-state-sha256-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  try {
    git(directory, "init", "--object-format=sha256", "--initial-branch=main");
  } catch {
    t.skip("The installed Git does not support SHA-256 repositories.");
    return;
  }
  git(directory, "config", "user.name", "OWC Fixture");
  git(directory, "config", "user.email", "fixture@openworkcommons.invalid");
  await writeFile(join(directory, "tracked.txt"), "sha256 repository\n");
  git(directory, "add", "tracked.txt");
  git(directory, "commit", "-m", "initial");

  const captured = await capture(directory);
  assert.equal(captured.state.object_format, "sha256");
  assert.match(captured.state.head_commit, /^[a-f0-9]{64}$/);
  assert.match(captured.state.head_tree, /^[a-f0-9]{64}$/);
  assert.match(captured.state.repository_id, /^urn:owc:repository:git:sha256:/);
});

test("rejects index entries Git is configured not to inspect", async (t) => {
  const repository = await createRepository(t);
  git(repository, "update-index", "--assume-unchanged", "tracked.txt");
  await writeFile(join(repository, "tracked.txt"), "hidden change\n");

  await assert.rejects(
    capture(repository),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "UNSUPPORTED_REPOSITORY_STATE",
  );
});

test("rejects shallow history whose root-derived identity could change", async (t) => {
  const source = await createRepository(t);
  await writeFile(join(source, "tracked.txt"), "second commit\n");
  git(source, "add", "tracked.txt");
  git(source, "commit", "-m", "second");
  const parent = await mkdtemp(join(tmpdir(), "owc-git-state-shallow-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const shallow = join(parent, "clone");
  git(parent, "clone", "--depth=1", "--no-local", source, shallow);

  await assert.rejects(
    capture(shallow),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "UNSUPPORTED_REPOSITORY_STATE",
  );

  const explicitlyIdentified = await captureGitState({
    cwd: shallow,
    capturedAt: CAPTURED_AT,
    runner,
    repositoryId: "urn:owc:repository:fixture-explicit-shallow",
  });
  assert.equal(
    explicitlyIdentified.state.repository_id,
    "urn:owc:repository:fixture-explicit-shallow",
  );
});

test("rejects impossible calendar timestamps before invoking Git", async () => {
  let invoked = false;
  const unusedRunner: GitCommandRunner = {
    async run() {
      invoked = true;
      throw new Error("must not run");
    },
  };

  await assert.rejects(
    captureGitState({
      cwd: ".",
      capturedAt: "2026-02-29T12:00:00Z",
      runner: unusedRunner,
    }),
    (error: unknown) =>
      error instanceof GitStateCaptureError &&
      error.code === "INVALID_CAPTURE_TIME",
  );
  assert.equal(invoked, false);
});

test("uses no network-capable Git command", async (t) => {
  const repository = await createRepository(t);
  const invocations: string[][] = [];
  const recordingRunner: GitCommandRunner = {
    run(request) {
      invocations.push([...request.args]);
      return runner.run(request);
    },
  };

  await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner: recordingRunner,
  });

  assert.ok(invocations.length > 0);
  for (const invocation of invocations) {
    const commandLine = invocation.join(" ");
    assert.doesNotMatch(
      commandLine,
      /(?:^| )(?:clone|fetch|pull|push|ls-remote|remote)(?: |$)/,
    );
    assert.match(commandLine, /protocol\.allow=never/);
  }
});

test("fails before hostile clean, smudge, or process filters can execute", async (t) => {
  for (const setting of ["clean", "smudge", "process"] as const) {
    const repository = await createRepository(t);
    await writeFile(
      join(repository, ".gitattributes"),
      "*.txt filter=hostile\n",
    );
    git(repository, "add", ".gitattributes");
    git(repository, "commit", "-m", "declare hostile filter");

    const marker = join(repository, `filter-${setting}-executed`);
    const filter = join(repository, `hostile-${setting}-filter.sh`);
    await writeFile(filter, '#!/bin/sh\nprintf "executed" > "$1"\ncat\n');
    await chmod(filter, 0o700);
    git(
      repository,
      "config",
      `filter.hostile.${setting}`,
      `${filter} ${marker}`,
    );
    await writeFile(join(repository, "tracked.txt"), `${setting} change\n`);

    await assert.rejects(
      captureGitState({
        cwd: repository,
        capturedAt: CAPTURED_AT,
        runner,
        limits: { commandTimeoutMs: 1_000 },
      }),
      (error: unknown) =>
        error instanceof GitStateCaptureError &&
        error.code === "UNSUPPORTED_REPOSITORY_STATE",
    );
    await assert.rejects(access(marker), (error: unknown) => {
      return (
        error instanceof Error &&
        "code" in error &&
        (error as NodeJS.ErrnoException).code === "ENOENT"
      );
    });
  }
});

async function createRepository(
  t: TestContext,
  initialBytes: string | Uint8Array = "initial\n",
): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "owc-git-state-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(directory, { recursive: true });
  git(directory, "init", "--initial-branch=main");
  git(directory, "config", "user.name", "OWC Fixture");
  git(directory, "config", "user.email", "fixture@openworkcommons.invalid");
  const filename =
    typeof initialBytes === "string" ? "tracked.txt" : "tracked.bin";
  await writeFile(join(directory, filename), initialBytes);
  git(directory, "add", filename);
  git(directory, "commit", "-m", "initial");
  return directory;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      LC_ALL: "C",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function capture(repository: string) {
  return captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
  });
}
