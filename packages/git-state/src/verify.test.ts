import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { captureGitState } from "./capture.js";
import { createNodeGitCommandRunner } from "./node-runner.js";
import type { GitCommandRunner, GitStateV0 } from "./types.js";
import { verifyExternalGitState } from "./verify.js";

const CAPTURED_AT = "2026-08-07T12:00:00Z";
const runner = createNodeGitCommandRunner();

test("matches an exact dirty repository using the declared include policy", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "dirty tracked state\n");
  await writeFile(
    join(repository, "untracked.txt"),
    "included untracked state\n",
  );
  const declared = await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
    untrackedPolicy: "include",
  });

  const invocations: string[][] = [];
  const recordingRunner: GitCommandRunner = {
    run(request) {
      invocations.push([...request.args]);
      return runner.run(request);
    },
  };
  const verified = await verifyExternalGitState({
    cwd: repository,
    declaredState: declared.state,
    runner: recordingRunner,
  });

  assert.deepEqual(verified, {
    status: "matched",
    reason: "exact_git_state_match",
  });
  assert.ok(invocations.length > 0);
  for (const invocation of invocations) {
    assert.doesNotMatch(
      invocation.join(" "),
      /(?:^| )(?:clone|fetch|pull|push|ls-remote|remote)(?: |$)/,
    );
    assert.match(invocation.join(" "), /protocol\.allow=never/);
  }
});

test("reports tracked dirty drift without returning patch content", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "first dirty state\n");
  const declared = await capture(repository);
  await writeFile(join(repository, "tracked.txt"), "second dirty state\n");

  const verified = await verifyExternalGitState({
    cwd: repository,
    declaredState: declared.state,
    runner,
  });
  assert.deepEqual(verified, {
    status: "mismatched",
    reason: "tracked_patch_mismatch",
  });
  assert.doesNotMatch(JSON.stringify(verified), /first dirty|second dirty/);
});

test("reports untracked digest drift independently from tracked state", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "new.txt"), "first untracked state\n");
  const declared = await capture(repository);
  await writeFile(join(repository, "new.txt"), "second untracked state\n");

  assert.deepEqual(
    await verifyExternalGitState({
      cwd: repository,
      declaredState: declared.state,
      runner,
    }),
    { status: "mismatched", reason: "untracked_manifest_mismatch" },
  );
});

test("reports unavailable for a directory that is not a Git worktree", async (t) => {
  const repository = await createRepository(t);
  const declared = await capture(repository);
  const outside = await mkdtemp(join(tmpdir(), "owc-git-verify-outside-"));
  t.after(() => rm(outside, { recursive: true, force: true }));

  assert.deepEqual(
    await verifyExternalGitState({
      cwd: outside,
      declaredState: declared.state,
      runner,
    }),
    { status: "unavailable", reason: "repository_unavailable" },
  );
});

test("fails closed before a hostile repository filter can execute", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "tracked.txt"), "declared dirty state\n");
  const declared = await capture(repository);
  const marker = join(repository, "HOSTILE_FILTER_EXECUTED");
  const filter = join(repository, "hostile-filter.sh");
  await writeFile(filter, `#!/bin/sh\nprintf executed > "${marker}"\ncat\n`);
  await chmod(filter, 0o700);
  git(repository, "config", "filter.hostile.clean", filter);

  assert.deepEqual(
    await verifyExternalGitState({
      cwd: repository,
      declaredState: declared.state,
      runner,
    }),
    { status: "unavailable", reason: "repository_state_unsupported" },
  );
  await assert.rejects(access(marker));
});

test("rejects a mixed include policy without touching Git", async (t) => {
  const repository = await createRepository(t);
  await writeFile(join(repository, "one.txt"), "one\n");
  await writeFile(join(repository, "two.txt"), "two\n");
  const captured = await captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
    untrackedPolicy: "include",
  });
  const [one, two] = captured.state.worktree.untracked;
  assert.ok(one?.included && two?.included);
  const mixed = {
    ...captured.state,
    worktree: {
      ...captured.state.worktree,
      untracked: [
        one,
        {
          path: two.path,
          digest: two.digest,
          byte_length: two.byte_length,
          included: false as const,
        },
      ],
    },
  } satisfies GitStateV0;
  let commands = 0;

  assert.deepEqual(
    await verifyExternalGitState({
      cwd: repository,
      declaredState: mixed,
      runner: {
        async run() {
          commands += 1;
          throw new Error("must not run");
        },
      },
    }),
    { status: "unavailable", reason: "declared_state_unsupported" },
  );
  assert.equal(commands, 0);
});

async function capture(repository: string) {
  return captureGitState({
    cwd: repository,
    capturedAt: CAPTURED_AT,
    runner,
  });
}

async function createRepository(t: TestContext): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "owc-git-verify-"));
  t.after(() => rm(repository, { recursive: true, force: true }));
  git(repository, "init", "--initial-branch=main");
  git(repository, "config", "user.name", "OWC Fixture");
  git(repository, "config", "user.email", "fixture@openworkcommons.invalid");
  await writeFile(join(repository, "tracked.txt"), "initial\n");
  git(repository, "add", "tracked.txt");
  git(repository, "commit", "-m", "initial");
  return repository;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      LC_ALL: "C",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}
