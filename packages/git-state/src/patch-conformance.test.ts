import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { decodeGitPatchArtifact, encodeGitPatchArtifact } from "./index.js";

type Vector = {
  format: string;
  encoding: string;
  sections: Array<{ name: string; payload: string }>;
  artifact: string;
  byte_length: number;
  digest: string;
};

test("matches the published v1 binary patch framing vector", async () => {
  const vector = JSON.parse(
    await readFile(
      new URL("../../../conformance/valid/git-patch-v1.json", import.meta.url),
      "utf8",
    ),
  ) as Vector;
  assert.equal(vector.format, "application/vnd.openworkcommons.git-patch-v1");
  assert.equal(vector.encoding, "base64url-unpadded");

  const index = Buffer.from(vector.sections[0]?.payload ?? "", "base64url");
  const worktree = Buffer.from(vector.sections[1]?.payload ?? "", "base64url");
  const encoded = encodeGitPatchArtifact({ index, worktree }, 1024);
  const published = Buffer.from(vector.artifact, "base64url");

  assert.deepEqual(encoded, published);
  assert.equal(encoded.byteLength, vector.byte_length);
  assert.equal(
    `sha256:${createHash("sha256").update(encoded).digest("hex")}`,
    vector.digest,
  );
  assert.deepEqual(decodeGitPatchArtifact(published), { index, worktree });
});
