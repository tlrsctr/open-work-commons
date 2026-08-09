import assert from "node:assert/strict";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createDeviceIdentityRuntime } from "./device-identity-runtime.js";
import { createWorkspaceStoreRuntime } from "./store-runtime.js";

test("diagnoses without creating, then reopens one public-only workspace identity", async (t) => {
  if (process.platform === "win32") {
    t.skip(
      "The POSIX local-file identity adapter deliberately refuses Windows.",
    );
    return;
  }
  const workspace = await mkdtemp(join(tmpdir(), "owc-cli-identity-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const runtime = createDeviceIdentityRuntime(workspace);

  const missing = await runtime.diagnose();
  assert.equal(missing.ok, false);
  assert.equal(missing.code, "not_found");
  await assert.rejects(stat(join(workspace, ".owc")), hasCode("ENOENT"));

  const workspaceStore = createWorkspaceStoreRuntime();
  const initialized = await workspaceStore.initialize(workspace);
  const first = await runtime.openOrCreate(initialized.store_path);
  const second = await runtime.openOrCreate(initialized.store_path);
  assert.equal(second.fingerprint, first.fingerprint);
  assert.deepEqual(Object.keys(first).sort(), [
    "algorithm",
    "fingerprint",
    "format",
    "key_id",
    "public_key",
    "public_key_spki",
    "schema_version",
  ]);

  const ready = await runtime.diagnose();
  assert.equal(ready.ok, true);
  if (ready.ok) {
    assert.deepEqual(ready.identity, first);
  }
  assert.deepEqual(await workspaceStore.health(workspace), {
    ok: true,
    checkedEvents: 0,
    checkedBlobs: 0,
    issues: [],
  });
});

function hasCode(code: string): (error: unknown) => boolean {
  return (error) =>
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code;
}
