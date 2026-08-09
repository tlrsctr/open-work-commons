import assert from "node:assert/strict";
import test from "node:test";

import { createNodeCommandRunner } from "./node-runtime.js";

test("captures a normally exiting child without timeout metadata", async () => {
  const result = await createNodeCommandRunner(2_000).run({
    command: process.execPath,
    args: [
      "-e",
      'process.stdout.write("normal-out"); process.stderr.write("normal-err");',
    ],
    cwd: process.cwd(),
  });

  assert.deepEqual(result, {
    exit_code: 0,
    stdout: "normal-out",
    stderr: "normal-err",
  });
});

test(
  "hard-kills a child that traps SIGTERM and resolves a fixed timeout result",
  { timeout: 5_000 },
  async () => {
    const runner = createNodeCommandRunner(1_000, 150, 150);
    const startedAt = Date.now();
    const result = await runner.run({
      command: process.execPath,
      args: [
        "-e",
        [
          'process.on("SIGTERM", () => process.stdout.write("IGNORED_SIGTERM\\n"));',
          'process.stdout.write("READY\\n");',
          "setInterval(() => undefined, 1000);",
        ].join(" "),
      ],
      cwd: process.cwd(),
    });
    const elapsedMs = Date.now() - startedAt;

    assert.deepEqual(
      {
        exit_code: result.exit_code,
        error_code: result.error_code,
        timed_out: result.timed_out,
        stderr: result.stderr,
      },
      {
        exit_code: null,
        error_code: "ETIMEDOUT",
        timed_out: true,
        stderr: "",
      },
    );
    assert.match(result.stdout, /^READY\nIGNORED_SIGTERM\n$/);
    assert.ok(elapsedMs >= 1_000, `settled too early after ${elapsedMs}ms`);
    assert.ok(elapsedMs < 3_000, `settled too late after ${elapsedMs}ms`);
  },
);
