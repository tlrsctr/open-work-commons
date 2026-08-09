import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createWorkspaceStoreRuntime } from "./store-runtime.js";

test("initializes and reopens an empty deny-by-default local store", async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), "owc-cli-store-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const runtime = createWorkspaceStoreRuntime();

  const initialized = await runtime.initialize(workspace);
  assert.equal(initialized.store_path, join(await realpath(workspace), ".owc"));
  assert.equal((await stat(initialized.store_path)).isDirectory(), true);
  assert.deepEqual(await runtime.health(workspace), {
    ok: true,
    checkedEvents: 0,
    checkedBlobs: 0,
    issues: [],
  });
});
