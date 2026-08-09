import assert from "node:assert/strict";
import test from "node:test";
import type {
  CommandRequest,
  CommandResult,
  CommandRunner,
} from "../../../packages/core/src/index.js";
import { createEntireCaptureProvider } from "./entire-provider.js";

const helpPayloads = new Map<string, unknown>([
  [
    "agent-help --json",
    {
      subcommands: [
        { name: "status" },
        { name: "agent" },
        { name: "checkpoint" },
      ],
    },
  ],
  ["agent-help status --json", { flags: [{ name: "json" }] }],
  [
    "agent-help agent --json",
    { subcommands: [{ name: "list" }, { name: "add" }, { name: "remove" }] },
  ],
  ["agent-help checkpoint --json", { subcommands: [{ name: "list" }] }],
  [
    "agent-help checkpoint list --json",
    {
      flags: [{ name: "json" }, { name: "pending" }, { name: "session" }],
    },
  ],
]);

type FakeOptions = {
  version?: CommandResult;
  status?: CommandResult;
};

function result(stdout: string, exit_code = 0): CommandResult {
  return { exit_code, stdout, stderr: "" };
}

function providerFor(options: FakeOptions, requests: CommandRequest[] = []) {
  const commandRunner: CommandRunner = {
    async run(request) {
      requests.push(request);
      const command = request.args.join(" ");
      if (command === "--version") {
        return options.version ?? result("Entire CLI 0.9.0\n");
      }
      if (command === "status --json") {
        return options.status ?? result(JSON.stringify({ enabled: true }));
      }
      const help = helpPayloads.get(command);
      if (help !== undefined) return result(JSON.stringify(help));
      throw new Error(`Unexpected command: ${request.command} ${command}`);
    },
  };
  return createEntireCaptureProvider(commandRunner, "/fixture/repository");
}

test("Entire provider uses the canonical adapter and retains no provider payload", async () => {
  const requests: CommandRequest[] = [];
  const provider = providerFor(
    {
      status: result(
        JSON.stringify({
          enabled: true,
          agents: { codex: { secret_adjacent_field: "not retained" } },
        }),
      ),
    },
    requests,
  );

  assert.deepEqual(await provider.status(), {
    schema_version: 1,
    provider: "entire",
    state: "ready",
    capture_ready: true,
    message: "Entire capture is enabled for this repository.",
  });
  assert.equal(requests[0]?.args.join(" "), "--version");
  assert.equal(requests.at(-1)?.args.join(" "), "status --json");
  assert.ok(
    requests.every(
      ({ command, cwd }) =>
        command === "entire" && cwd === "/fixture/repository",
    ),
  );
  assert.doesNotMatch(JSON.stringify(await provider.status()), /not retained/);
});

test("Entire provider distinguishes disabled, absent, failed, malformed, and old versions", async () => {
  const disabled = await providerFor({
    status: result(JSON.stringify({ enabled: false, error: "private detail" })),
  }).status();
  assert.equal(disabled.state, "disabled");
  assert.doesNotMatch(disabled.message, /private detail/);

  const missing = await providerFor({
    version: {
      exit_code: null,
      stdout: "",
      stderr: "private path",
      error_code: "ENOENT",
    },
  }).status();
  assert.equal(missing.state, "unavailable");
  assert.doesNotMatch(missing.message, /private path/);

  const failed = await providerFor({ status: result("", 1) }).status();
  assert.equal(failed.state, "error");

  const invalid = await providerFor({ status: result("not-json") }).status();
  assert.equal(invalid.state, "invalid_output");

  const old = await providerFor({
    version: result("Entire CLI 0.8.9\n"),
  }).status();
  assert.equal(old.state, "unavailable");
  assert.match(old.message, />=0\.9\.0/);
});
