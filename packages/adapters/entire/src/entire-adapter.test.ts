import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createEntireAdapter,
  type CommandInvocation,
  type CommandResult,
  type CommandRunner,
} from "./entire-adapter.js";

const ROOT_HELP = {
  command: "entire",
  subcommands: [
    { name: "status" },
    { name: "agent" },
    { name: "checkpoint" },
    { name: "login" },
    { name: "api" },
  ],
};

const STATUS_HELP = {
  command: "entire status",
  flags: [{ name: "json" }, { name: "detailed" }],
};

const AGENT_HELP = {
  command: "entire agent",
  subcommands: [{ name: "list" }, { name: "add" }, { name: "remove" }],
};

const CHECKPOINT_HELP = {
  command: "entire checkpoint",
  subcommands: [{ name: "list" }, { name: "explain" }, { name: "search" }],
};

const CHECKPOINT_LIST_HELP = {
  command: "entire checkpoint list",
  flags: [{ name: "json" }, { name: "pending" }, { name: "session" }],
};

const CHECKPOINT_EXPLAIN_HELP = {
  command: "entire checkpoint explain",
  flags: [
    { name: "json" },
    { name: "transcript" },
    { name: "raw-transcript" },
    { name: "generate" },
  ],
};

test("reports Entire 0.9 local capabilities without auth or transcripts", async () => {
  const fake = createFakeRunner({
    status: {
      enabled: true,
      agents: [
        { name: "Claude Code", installed: true },
        { id: "codex", status: "enabled" },
        { id: "unused-agent", installed: false },
      ],
      transcript: "must-not-leave-the-adapter",
      active_sessions: [{ raw_transcript: "also-private" }],
    },
  });

  const report = await createEntireAdapter({ runner: fake.runner }).inspect({
    cwd: "/work/repository",
  });

  assert.deepEqual(report.installation, {
    installed: true,
    version: "0.9.0",
    supported: true,
    minimumVersion: "0.9.0",
  });
  assert.deepEqual(report.repository, { enabled: true, state: "known" });
  assert.deepEqual(report.capabilities.agents, {
    available: true,
    list: true,
    add: true,
    remove: true,
    installed: ["claude-code", "codex"],
    installedState: "known",
  });
  assert.deepEqual(report.capabilities.checkpoints, {
    available: true,
    list: true,
    json: true,
    pending: true,
    sessionFilter: true,
    detail: true,
    detailJson: true,
    localOnlyGuaranteed: false,
    boundary: "provider-cli-may-fetch-remote-checkpoint-data",
  });
  assert.deepEqual(report.access, { localOnly: true, accountRequired: false });
  assert.deepEqual(report.dataPolicy, { rawTranscripts: "excluded" });

  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /must-not-leave|also-private/);
  assert.ok(fake.calls.every((call) => call.cwd === "/work/repository"));
  assert.ok(
    fake.calls.every(
      (call) =>
        !call.args.includes("login") &&
        !call.args.includes("auth") &&
        !call.args.includes("api") &&
        !call.args.includes("--transcript"),
    ),
  );
});

test("reports a disabled repository without requiring an account", async () => {
  const fake = createFakeRunner({ status: { status: "disabled", agents: {} } });

  const report = await createEntireAdapter({ runner: fake.runner }).inspect();

  assert.equal(report.repository.enabled, false);
  assert.equal(report.repository.state, "known");
  assert.equal(report.capabilities.agents.installedState, "known");
  assert.deepEqual(report.capabilities.agents.installed, []);
  assert.equal(report.access.accountRequired, false);
});

test("stops after detecting an unsupported pre-0.9 installation", async () => {
  const calls: CommandInvocation[] = [];
  const runner: CommandRunner = async (invocation) => {
    calls.push(invocation);
    return result("Entire CLI 0.8.9\n");
  };

  const report = await createEntireAdapter({ runner }).inspect();

  assert.equal(report.installation.installed, true);
  assert.equal(report.installation.version, "0.8.9");
  assert.equal(report.installation.supported, false);
  assert.deepEqual(report.diagnostics, ["entire_version_unsupported"]);
  assert.deepEqual(
    calls.map((call) => call.args),
    [["--version"]],
  );
});

test("accepts later major versions", async () => {
  const fake = createFakeRunner({
    version: "Entire CLI 1.2.3\n",
    status: { enabled: true, agent_integrations: { codex: true } },
  });

  const report = await createEntireAdapter({ runner: fake.runner }).inspect();

  assert.equal(report.installation.version, "1.2.3");
  assert.equal(report.installation.supported, true);
  assert.deepEqual(report.capabilities.agents.installed, ["codex"]);
});

test("reports an absent executable without leaking runner errors", async () => {
  const runner: CommandRunner = async () => {
    throw new Error("ENOENT with private/local/path");
  };

  const report = await createEntireAdapter({ runner }).inspect();

  assert.equal(report.installation.installed, false);
  assert.equal(report.repository.enabled, null);
  assert.deepEqual(report.diagnostics, ["entire_not_installed"]);
  assert.doesNotMatch(JSON.stringify(report), /private\/local\/path/);
});

test("fails closed when status is malformed and returns no raw command output", async () => {
  const fake = createFakeRunner({
    statusOutput: "raw transcript bytes, not JSON",
  });

  const report = await createEntireAdapter({ runner: fake.runner }).inspect();

  assert.equal(report.repository.enabled, null);
  assert.equal(report.repository.state, "unknown");
  assert.ok(report.diagnostics.includes("entire_status_unrecognized"));
  assert.doesNotMatch(JSON.stringify(report), /raw transcript bytes/);
});

test("strict-local checkpoint discovery reports the fetch boundary without listing", async () => {
  const fake = createFakeRunner({ status: { enabled: true } });

  const discovery = await createEntireAdapter({
    runner: fake.runner,
  }).discoverCheckpoints({ cwd: "/work/repository" });

  assert.equal(discovery.status, "unavailable");
  assert.equal(
    discovery.reason,
    "provider_cli_may_fetch_remote_checkpoint_data",
  );
  assert.deepEqual(discovery.capabilities, {
    structuredList: true,
    structuredDetail: true,
    localOnlyGuaranteed: false,
  });
  assert.ok(
    fake.calls.every(
      (call) =>
        call.args[0] !== "checkpoint" &&
        !call.args.includes("--transcript") &&
        !call.args.includes("--raw-transcript"),
    ),
  );
});

test(
  "bounds a real child that traps SIGTERM and exposes only fixed diagnostics",
  { timeout: 5_000 },
  async () => {
    const fixture = fileURLToPath(
      new URL("../test/fixtures/hanging-entire.mjs", import.meta.url),
    );
    const directory = await mkdtemp(join(tmpdir(), "owc-entire-timeout-"));
    let fallbackTimer: NodeJS.Timeout | undefined;

    try {
      await access(fixture);
      const startedAt = Date.now();
      const inspection = createEntireAdapter({
        binary: fixture,
        probeTimeoutMs: 500,
        terminationGraceMs: 100,
      }).inspect({ cwd: directory });
      const report = await Promise.race([
        inspection,
        new Promise<never>((_resolve, reject) => {
          fallbackTimer = setTimeout(
            () => reject(new Error("timeout regression did not settle")),
            3_000,
          );
        }),
      ]);

      assert.ok(Date.now() - startedAt < 3_000);
      assert.equal(
        await readFile(join(directory, "sigterm-observed"), "utf8"),
        "observed\n",
      );
      assert.equal(await fixtureIsRunning(directory), false);
      assert.equal(report.installation.installed, false);
      assert.deepEqual(report.diagnostics, ["entire_not_installed"]);
      assert.doesNotMatch(
        JSON.stringify(report),
        /private-timeout-(?:stdout|stderr)/,
      );
    } finally {
      if (fallbackTimer !== undefined) clearTimeout(fallbackTimer);
      await terminateFixtureIfRunning(directory);
      await rm(directory, { recursive: true, force: true });
    }
  },
);

interface FakeRunnerOptions {
  readonly version?: string;
  readonly status?: JsonRecord;
  readonly statusOutput?: string;
}

type JsonRecord = Record<string, unknown>;

function createFakeRunner(options: FakeRunnerOptions): {
  readonly runner: CommandRunner;
  readonly calls: CommandInvocation[];
} {
  const calls: CommandInvocation[] = [];
  const runner: CommandRunner = async (invocation) => {
    calls.push(invocation);
    const command = invocation.args.join(" ");
    if (command === "--version") {
      return result(options.version ?? "Entire CLI 0.9.0\n");
    }
    if (command === "agent-help --json") return jsonResult(ROOT_HELP);
    if (command === "agent-help status --json") return jsonResult(STATUS_HELP);
    if (command === "agent-help agent --json") return jsonResult(AGENT_HELP);
    if (command === "agent-help checkpoint --json") {
      return jsonResult(CHECKPOINT_HELP);
    }
    if (command === "agent-help checkpoint list --json") {
      return jsonResult(CHECKPOINT_LIST_HELP);
    }
    if (command === "agent-help checkpoint explain --json") {
      return jsonResult(CHECKPOINT_EXPLAIN_HELP);
    }
    if (command === "status --json") {
      return result(
        options.statusOutput ??
          JSON.stringify(options.status ?? { enabled: true }),
      );
    }
    throw new Error(`unexpected command: ${command}`);
  };
  return { runner, calls };
}

function jsonResult(value: unknown): CommandResult {
  return result(JSON.stringify(value));
}

function result(stdout: string, exitCode = 0): CommandResult {
  return { exitCode, stdout, stderr: "" };
}

async function terminateFixtureIfRunning(directory: string): Promise<void> {
  try {
    const pid = await readFixturePid(directory);
    if (!Number.isSafeInteger(pid) || pid <= 0) return;
    process.kill(pid, "SIGKILL");
  } catch {
    // The runner already reaped the child or it never started.
  }
}

async function fixtureIsRunning(directory: string): Promise<boolean> {
  const pid = await readFixturePid(directory);
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (isErrnoException(error) && error.code === "ESRCH") return false;
    throw error;
  }
}

async function readFixturePid(directory: string): Promise<number> {
  return Number((await readFile(join(directory, "probe-pid"), "utf8")).trim());
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}
