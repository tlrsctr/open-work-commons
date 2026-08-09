import assert from "node:assert/strict";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLogicalArchive } from "../../../packages/archive/src/index.js";
import {
  ArchiveDirectoryError,
  createDirectoryArchiveLoader,
} from "./archive-directory.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const goldenRoot = join(repositoryRoot, "conformance/valid/minimal");
const signedPaths = [
  "checkpoints/checkpoint.json",
  "events/session-started.json",
  "state/git-state.json",
] as const;

test("loads only signed logical entries and ignores an adjacent resume derivative", async () => {
  const archive = await createDirectoryArchiveLoader().load(goldenRoot);
  assert.deepEqual(
    archive.entries.map((entry) => entry.path),
    signedPaths,
  );
  assert.equal(
    archive.entries.some((entry) => entry.path.startsWith("resume/")),
    false,
  );
  assert.equal(verifyLogicalArchive(archive).integrity.valid, true);
});

test("preserves missing listed entries for a fixed verifier diagnostic", async (t) => {
  const root = await copyGoldenFixture(t);
  await rm(join(root, "state/git-state.json"));

  const archive = await createDirectoryArchiveLoader().load(root);
  const result = verifyLogicalArchive(archive);
  assert.equal(result.integrity.valid, false);
  assert.ok(
    result.integrity.issues.some((issue) => issue.code === "missing_entry"),
  );
});

test("never follows a listed symbolic link", async (t) => {
  const root = await copyGoldenFixture(t);
  const checkpointPath = join(root, "checkpoints/checkpoint.json");
  await rm(checkpointPath);
  await symlink(
    join(goldenRoot, "checkpoints/checkpoint.json"),
    checkpointPath,
  );

  const archive = await createDirectoryArchiveLoader().load(root);
  const checkpoint = archive.entries.find(
    (entry) => entry.path === "checkpoints/checkpoint.json",
  );
  assert.equal(checkpoint?.kind, "symlink");
  assert.equal(checkpoint?.bytes.byteLength, 0);
  const result = verifyLogicalArchive(archive);
  assert.ok(
    result.integrity.issues.some((issue) => issue.code === "special_entry"),
  );
});

test("fails with a fixed error for a non-directory or oversized manifest", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "owc-archive-loader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = join(root, "not-a-directory");
  await writeFile(file, "not an archive");
  await assert.rejects(
    createDirectoryArchiveLoader().load(file),
    (error) =>
      error instanceof ArchiveDirectoryError &&
      error.code === "invalid_archive_directory",
  );

  const oversized = join(root, "oversized");
  await mkdir(oversized);
  await writeFile(
    join(oversized, "archive-manifest.json"),
    Buffer.alloc(1024 * 1024 + 1),
  );
  await assert.rejects(
    createDirectoryArchiveLoader().load(oversized),
    (error) =>
      error instanceof ArchiveDirectoryError && error.code === "resource_limit",
  );
});

async function copyGoldenFixture(t: TestContext): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "owc-archive-loader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    join(root, "archive-manifest.json"),
    await readFile(join(goldenRoot, "archive-manifest.json")),
  );
  for (const path of signedPaths) {
    const target = join(root, path);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(join(goldenRoot, path), target);
  }
  return root;
}
