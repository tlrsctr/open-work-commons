import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";

import {
  verifyLogicalArchive,
  type LogicalArchive,
} from "../../../packages/archive/src/index.js";
import { createDirectoryArchiveLoader } from "./archive-directory.js";
import {
  createHandoffFileRuntime,
  HandoffFileError,
} from "./handoff-file-runtime.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const goldenRoot = join(repositoryRoot, "conformance/valid/minimal");
const goldenEntries = [
  "checkpoints/checkpoint.json",
  "events/session-started.json",
  "state/git-state.json",
] as const;

test("reads bounded regular inputs with O_NOFOLLOW and duplicate-key rejection", async (t) => {
  const root = await temporaryDirectory(t);
  const runtime = createHandoffFileRuntime();
  const planPath = join(root, "plan.json");
  await writeFile(planPath, '{"actor":{"id":"human:test"}}');
  const parsed = await runtime.readPlan(planPath);
  assert.equal(
    (parsed as unknown as { actor: { id: string } }).actor.id,
    "human:test",
  );

  const duplicate = join(root, "duplicate.json");
  await writeFile(duplicate, '{"actor":{},"actor":{}}');
  await assert.rejects(runtime.readPlan(duplicate), hasCode("plan_invalid"));

  const linked = join(root, "linked.json");
  await symlink(planPath, linked);
  await assert.rejects(runtime.readPlan(linked), hasCode("input_unavailable"));

  const oversized = join(root, "oversized.json");
  await writeFile(oversized, Buffer.alloc(256 * 1024 + 1, 0x20));
  await assert.rejects(
    runtime.readEntireCheckpointDetail(oversized),
    hasCode("input_resource_limit"),
  );
});

test("atomically publishes a verified unpacked archive with owner-only modes", async (t) => {
  if (process.platform === "win32") {
    t.skip(
      "The owner-only local archive publisher deliberately targets POSIX.",
    );
    return;
  }
  const root = await temporaryDirectory(t);
  const output = join(root, "published");
  const runtime = createHandoffFileRuntime();
  const archive = await goldenArchive();

  await runtime.assertOutputAvailable(output);
  const summary = await runtime.publishArchive(output, archive);
  assert.equal(summary.entryCount, goldenEntries.length);
  assert.ok(summary.totalBytes > archive.manifestBytes.byteLength);
  assert.equal((await stat(output)).mode & 0o777, 0o700);
  assert.equal(
    (await stat(join(output, "archive-manifest.json"))).mode & 0o777,
    0o600,
  );
  for (const path of goldenEntries) {
    assert.equal((await stat(join(output, path))).mode & 0o777, 0o600);
    assert.equal((await stat(dirname(join(output, path)))).mode & 0o777, 0o700);
  }

  const loaded = await createDirectoryArchiveLoader().load(output);
  const verification = verifyLogicalArchive(loaded);
  assert.equal(verification.integrity.valid, true);
  assert.equal(verification.signer.signatureValid, true);
  assert.deepEqual(
    loaded.entries.map((entry) => entry.path),
    goldenEntries,
  );
});

test("never overwrites an existing file, directory, or symbolic link", async (t) => {
  const root = await temporaryDirectory(t);
  const runtime = createHandoffFileRuntime();
  const archive = await goldenArchive();
  const existingFile = join(root, "existing-file");
  await writeFile(existingFile, "KEEP_ME");
  await assert.rejects(
    runtime.publishArchive(existingFile, archive),
    hasCode("output_exists"),
  );
  assert.equal(await readFile(existingFile, "utf8"), "KEEP_ME");

  const existingDirectory = join(root, "existing-directory");
  await mkdir(existingDirectory);
  await writeFile(join(existingDirectory, "canary"), "KEEP_DIRECTORY");
  await assert.rejects(
    runtime.publishArchive(existingDirectory, archive),
    hasCode("output_exists"),
  );
  assert.equal(
    await readFile(join(existingDirectory, "canary"), "utf8"),
    "KEEP_DIRECTORY",
  );

  const linked = join(root, "linked-output");
  await symlink(existingDirectory, linked);
  await assert.rejects(
    runtime.publishArchive(linked, archive),
    hasCode("output_exists"),
  );
  assert.equal(
    await readFile(join(existingDirectory, "canary"), "utf8"),
    "KEEP_DIRECTORY",
  );
});

test("two concurrent publishers cannot both claim one output", async (t) => {
  const root = await temporaryDirectory(t);
  const output = join(root, "single-winner");
  const runtime = createHandoffFileRuntime();
  const archive = await goldenArchive();
  const results = await Promise.allSettled([
    runtime.publishArchive(output, archive),
    runtime.publishArchive(output, archive),
  ]);
  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejected = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.ok(rejected);
  assert.equal(rejected.reason instanceof HandoffFileError, true);
  assert.equal((rejected.reason as HandoffFileError).code, "output_exists");
  const verification = verifyLogicalArchive(
    await createDirectoryArchiveLoader().load(output),
  );
  assert.equal(verification.integrity.valid, true);
});

test("rejects archive path escape before creating the output", async (t) => {
  const root = await temporaryDirectory(t);
  const output = join(root, "must-not-exist");
  const runtime = createHandoffFileRuntime();
  const archive = await goldenArchive();
  const malicious: LogicalArchive = {
    manifestBytes: archive.manifestBytes,
    entries: [{ path: "../escape", bytes: new Uint8Array([1]), kind: "file" }],
  };
  await assert.rejects(
    runtime.publishArchive(output, malicious),
    hasCode("archive_invalid"),
  );
  await assert.rejects(stat(output), hasFsCode("ENOENT"));
  await assert.rejects(stat(join(root, "escape")), hasFsCode("ENOENT"));
});

test("refuses to publish inside the private workspace store", async (t) => {
  const root = await temporaryDirectory(t);
  const workspace = join(root, "workspace");
  const privateStore = join(workspace, ".owc");
  await mkdir(privateStore, { recursive: true });
  const runtime = createHandoffFileRuntime(workspace);
  await assert.rejects(
    runtime.assertOutputAvailable(join(privateStore, "archive")),
    hasCode("output_unsafe"),
  );
});

async function goldenArchive(): Promise<LogicalArchive> {
  return {
    manifestBytes: await readFile(join(goldenRoot, "archive-manifest.json")),
    entries: await Promise.all(
      goldenEntries.map(async (path) => ({
        path,
        bytes: await readFile(join(goldenRoot, path)),
        kind: "file",
      })),
    ),
  };
}

async function temporaryDirectory(t: TestContext): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "owc-handoff-files-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function hasCode(code: HandoffFileError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof HandoffFileError && error.code === code;
}

function hasFsCode(code: string): (error: unknown) => boolean {
  return (error) =>
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code;
}
