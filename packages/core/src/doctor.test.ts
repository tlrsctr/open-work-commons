import assert from "node:assert/strict";
import test from "node:test";
import type {
  CaptureProvider,
  CommandRequest,
  CommandResult,
} from "./index.js";
import { ExitCode, runDoctor } from "./index.js";

test("doctor succeeds with injected filesystem, Git, and provider dependencies", async () => {
  const requests: CommandRequest[] = [];
  const provider: CaptureProvider = {
    id: "fixture",
    async status() {
      return {
        schema_version: 1,
        provider: "fixture",
        state: "ready",
        capture_ready: true,
        message: "Fixture capture is ready.",
      };
    },
  };
  const report = await runDoctor({
    cwd: "/fixture/repository",
    node_version: "v22.14.0",
    file_system: {
      async can_access() {
        return true;
      },
    },
    command_runner: {
      async run(request): Promise<CommandResult> {
        requests.push(request);
        return { exit_code: 0, stdout: "ok", stderr: "" };
      },
    },
    providers: [provider],
  });

  assert.equal(report.ok, true);
  assert.equal(report.exit_code, ExitCode.success);
  assert.deepEqual(
    report.checks.map((check) => check.id),
    [
      "runtime.node",
      "filesystem.cwd",
      "dependency.git",
      "git.repository",
      "provider.fixture",
    ],
  );
  assert.deepEqual(
    requests.map(({ command, args }) => [command, args]),
    [
      ["git", ["--version"]],
      ["git", ["rev-parse", "--show-toplevel"]],
    ],
  );
});

test("doctor reports deterministic dependency and readiness failures", async () => {
  const report = await runDoctor({
    cwd: "/missing",
    node_version: "v20.0.0",
    file_system: {
      async can_access() {
        return false;
      },
    },
    command_runner: {
      async run() {
        return {
          exit_code: null,
          stdout: "",
          stderr: "",
          error_code: "ENOENT",
        };
      },
    },
    providers: [
      {
        id: "fixture",
        async status() {
          return {
            schema_version: 1,
            provider: "fixture",
            state: "unavailable",
            capture_ready: false,
            message: "Fixture is unavailable.",
          };
        },
      },
    ],
  });

  assert.equal(report.ok, false);
  assert.equal(report.exit_code, ExitCode.notReady);
  assert.equal(
    report.checks.find((check) => check.id === "dependency.git")?.exit_code,
    ExitCode.dependencyUnavailable,
  );
  assert.equal(
    report.checks.find((check) => check.id === "git.repository")?.status,
    "fail",
  );
});
