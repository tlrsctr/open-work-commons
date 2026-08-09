import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import test from "node:test";

import { compileLocalSchemas, repositoryRoot } from "../harness/src/harness.js";
import {
  buildMaliciousCorpus,
  CorpusFailure,
  loadGoldenLogicalArchive,
  manifestObject,
  memberObject,
  secretCanary,
  specialMemberKinds,
  unsafePathCases,
  verifyWithIndependentOracle,
  type MutationVector,
  type OracleSuccess,
} from "./src/index.js";

test("malicious oracle is independent from archive and resume implementation code", async () => {
  const sourceRoot = resolve(repositoryRoot, "conformance/malicious/src");
  const sources = await readTree(sourceRoot);
  const joined = sources.map((file) => file.bytes.toString("utf8")).join("\n");

  for (const forbidden of [
    "packages/archive",
    "packages/resume",
    "node:child_process",
    "node:vm",
    "eval(",
    "new Function",
  ]) {
    assert.equal(joined.includes(forbidden), false, forbidden);
  }
});

test("golden logical archive passes the independent malicious-corpus oracle", async () => {
  const golden = await loadGoldenLogicalArchive();
  const report = await verifyWithIndependentOracle(golden);

  assert.equal(report.integrityValid, true);
  assert.equal(report.signerTrusted, true);
  assert.deepEqual(report.verifiedEntries, [
    "checkpoints/checkpoint.json",
    "events/session-started.json",
    "state/git-state.json",
  ]);
  assert.equal(report.ignoredEntryCount, 0);
});

test("derives a deterministic and uniquely named mutation corpus from the golden archive", async () => {
  const first = await buildMaliciousCorpus();
  const second = await buildMaliciousCorpus();
  const ids = first.map((vector) => vector.id);

  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(fingerprintCorpus(first), fingerprintCorpus(second));
  assert.equal(
    ids.filter((id) => id.startsWith("unsafe-manifest-path-")).length,
    unsafePathCases.length,
  );
  assert.equal(
    ids.filter((id) => id.startsWith("unsafe-logical-path-")).length,
    unsafePathCases.length,
  );
  assert.equal(
    ids.filter((id) => id.startsWith("special-member-")).length,
    specialMemberKinds.length,
  );
  assert.deepEqual(
    ids.filter((id) => id.startsWith("limit-")),
    [
      "limit-packed-bytes",
      "limit-expanded-bytes",
      "limit-entry-count",
      "limit-individual-entry-bytes",
      "limit-json-depth",
      "limit-json-string-bytes",
    ],
  );
});

test("every malicious vector has a stable result and safe affected object", async (t) => {
  const corpus = await buildMaliciousCorpus();

  for (const vector of corpus) {
    await t.test(vector.id, async () => {
      const expected = vector.expected;
      if (expected.outcome === "failure") {
        await assert.rejects(
          () => verifyWithIndependentOracle(vector.archive, vector.limits),
          (error: unknown) => {
            assert.ok(error instanceof CorpusFailure);
            assert.equal(error.category, expected.category);
            assert.equal(error.affectedObject, expected.affectedObject);
            assert.match(error.affectedObject, /^[A-Za-z0-9_./\[\]-]+$/);
            assertDiagnosticExcludesHostileText(
              error,
              vector.hostileText ?? [],
            );
            return true;
          },
        );
        return;
      }

      const report = await verifyWithIndependentOracle(
        vector.archive,
        vector.limits,
      );
      assert.equal(report.ignoredEntryCount, expected.ignoredEntryCount);
      assertSuccessCase(vector, report);
    });
  }
});

test("evidence identity substitution passes schemas before semantic rejection", async () => {
  const schemas = await compileLocalSchemas();
  const corpus = await buildMaliciousCorpus();
  const vector = corpus.find(
    (candidate) => candidate.id === "evidence-identity-substitution",
  );
  assert.ok(vector);

  assert.equal(
    schemas.validate("archiveManifest", manifestObject(vector.archive)).valid,
    true,
  );
  assert.equal(
    schemas.validate(
      "checkpoint",
      memberObject(vector.archive, "checkpoints/checkpoint.json"),
    ).valid,
    true,
  );
  assert.equal(
    schemas.validate(
      "evidence",
      memberObject(vector.archive, "evidence/substituted.json"),
    ).valid,
    true,
  );
  await assert.rejects(
    () => verifyWithIndependentOracle(vector.archive, vector.limits),
    (error: unknown) =>
      error instanceof CorpusFailure &&
      error.category === "evidence-identity-substitution" &&
      error.affectedObject === "checkpoint.evidence.identity",
  );
});

test("resource vectors remain bounded and construct no exhaustion-sized fixture", async () => {
  const corpus = await buildMaliciousCorpus();
  for (const vector of corpus) {
    const memberBytes = vector.archive.members.reduce(
      (total, member) => total + member.bytes.byteLength,
      0,
    );
    assert.ok(vector.archive.manifestBytes.byteLength < 32 * 1024, vector.id);
    assert.ok(memberBytes < 64 * 1024, vector.id);
    assert.ok(
      vector.archive.members.every(
        (member) => member.bytes.byteLength < 32 * 1024,
      ),
      vector.id,
    );
  }
});

test("secret canary is absent from fixture data and every generated archive", async () => {
  const conformanceFiles = await readTree(
    resolve(repositoryRoot, "conformance"),
  );
  const fixtureData = conformanceFiles.filter(
    (file) => extname(file.path) === ".json",
  );
  for (const file of fixtureData) {
    assert.equal(
      file.bytes.includes(Buffer.from(secretCanary)),
      false,
      file.path,
    );
  }

  const specification = conformanceFiles.find((file) =>
    file.path.endsWith("tampered-archive.md"),
  );
  assert.ok(specification);
  assert.equal(
    specification.bytes.includes(Buffer.from(secretCanary)),
    true,
    "The human-readable test specification may name the synthetic canary.",
  );

  const corpus = await buildMaliciousCorpus();
  for (const vector of corpus) {
    assert.equal(
      Buffer.from(vector.archive.manifestBytes).includes(
        Buffer.from(secretCanary),
      ),
      false,
      `${vector.id}:manifest`,
    );
    for (const member of vector.archive.members) {
      assert.equal(
        Buffer.from(member.bytes).includes(Buffer.from(secretCanary)),
        false,
        `${vector.id}:member`,
      );
    }
  }
});

function assertSuccessCase(
  vector: MutationVector,
  report: OracleSuccess,
): void {
  if (vector.id === "unlisted-file-ignored") {
    assert.equal(
      report.verifiedEntries.includes("events/injected.json"),
      false,
    );
    assert.equal(
      report.resumeEligibleEntries.includes("events/injected.json"),
      false,
    );
    assert.equal(
      JSON.stringify(report.untrustedContent).includes("must-not-be-exposed"),
      false,
    );
  }

  if (vector.id === "prompt-injection-remains-data") {
    const injection = vector.hostileText?.[0];
    assert.ok(injection);
    const item = report.untrustedContent.find(
      (candidate) => candidate.value === injection,
    );
    assert.deepEqual(item, {
      source: "events/session-started.json",
      value: injection,
      executionAllowed: false,
    });
    assert.deepEqual(Object.keys(item).sort(), [
      "executionAllowed",
      "source",
      "value",
    ]);
  }
}

function assertDiagnosticExcludesHostileText(
  error: CorpusFailure,
  hostileText: readonly string[],
): void {
  const diagnostic = `${error.name}\n${error.message}\n${error.category}\n${error.affectedObject}`;
  for (const hostile of hostileText) {
    if (hostile.length === 0) continue;
    assert.equal(diagnostic.includes(hostile), false);
  }
}

function fingerprintCorpus(
  vectors: readonly MutationVector[],
): readonly string[] {
  return vectors.map((vector) => {
    const hash = createHash("sha256");
    hash.update(
      JSON.stringify({
        id: vector.id,
        manifest: digestBytes(vector.archive.manifestBytes),
        members: vector.archive.members.map((member) => ({
          path: member.logicalPath,
          kind: member.kind,
          bytes: digestBytes(member.bytes),
        })),
        trustAnchors: [...vector.archive.trustAnchors].sort(compareCodeUnits),
        expected: vector.expected,
        limits: vector.limits ?? null,
        hostileText: vector.hostileText ?? [],
      }),
    );
    return hash.digest("hex");
  });
}

function digestBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function compareCodeUnits(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

async function readTree(
  root: string,
): Promise<readonly { path: string; bytes: Buffer }[]> {
  const result: Array<{ path: string; bytes: Buffer }> = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) {
      result.push(...(await readTree(path)));
    } else if (entry.isFile() && extname(entry.name) !== ".map") {
      result.push({ path, bytes: await readFile(path) });
    }
  }
  return result;
}
