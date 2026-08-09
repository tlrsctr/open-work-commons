import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import {
  checkArchivePath,
  compileLocalSchemas,
  ConformanceFailure,
  goldenFixtureRoot,
  loadGoldenFixture,
  manifestSigningProjection,
  repositoryRoot,
  resolveGoldenReferences,
  schemaFiles,
  validateGoldenObjects,
  verifyEntryIntegrity,
  verifyGoldenConformance,
  verifyInlinePayloadDigest,
  verifyManifestSignature,
  verifyEvidenceReference,
  type ArchiveEntry,
  type CheckpointEvidence,
  type EvidenceObject,
} from "./src/index.js";
import { canonicalJsonBytes } from "./src/canonical-json.js";
import { sha256 } from "./src/crypto.js";
import { parseJsonSafely, SafeJsonError } from "./src/safe-json.js";

test("is an independent oracle with no archive-package imports", async () => {
  const sources = await Promise.all(
    [
      "canonical-json.ts",
      "crypto.ts",
      "harness.ts",
      "index.ts",
      "path.ts",
      "safe-json.ts",
    ].map((filename) =>
      readFile(
        resolve(repositoryRoot, "conformance/harness/src", filename),
        "utf8",
      ),
    ),
  );

  assert.equal(
    sources.some((source) => source.includes("packages/archive")),
    false,
  );
});

test("independent JSON parsing rejects duplicate object keys", () => {
  const duplicate = Buffer.from('{"archive_id":"first","archive_id":"second"}');

  assert.throws(
    () =>
      parseJsonSafely(duplicate, {
        maxDepth: 16,
        maxStringBytes: 1024,
      }),
    (error: unknown) =>
      error instanceof SafeJsonError && error.kind === "duplicate-key",
  );
});

test("compiles all six Draft 2020-12 schemas locally and validates the golden objects", async () => {
  const schemas = await compileLocalSchemas(repositoryRoot);
  const fixture = await loadGoldenFixture(goldenFixtureRoot);

  assert.deepEqual(
    Object.keys(schemas.schemaIds).sort(),
    Object.keys(schemaFiles).sort(),
  );
  assert.doesNotThrow(() => validateGoldenObjects(schemas, fixture));
});

test("accepts only the eight core event types or a reverse-DNS extension type", async () => {
  const schemas = await compileLocalSchemas();
  const validExtension = JSON.parse(
    await readFile(
      resolve(
        repositoryRoot,
        "conformance/valid/events/namespaced-extension.json",
      ),
      "utf8",
    ),
  ) as unknown;
  const invalidUnknown = JSON.parse(
    await readFile(
      resolve(
        repositoryRoot,
        "conformance/invalid/events/unknown-unnamespaced-type.json",
      ),
      "utf8",
    ),
  ) as unknown;

  assert.equal(schemas.validate("event", validExtension).valid, true);
  assert.equal(schemas.validate("event", invalidUnknown).valid, false);
});

test("requires the portable OWC event identity in events and checkpoint references", async () => {
  const schemas = await compileLocalSchemas();
  const invalidEvent = JSON.parse(
    await readFile(
      resolve(
        repositoryRoot,
        "conformance/invalid/events/non-owc-identity.json",
      ),
      "utf8",
    ),
  ) as unknown;
  const fixture = await loadGoldenFixture();
  const checkpoint = structuredClone(fixture.checkpoint) as unknown as {
    event_refs: Array<{ event_id: string }>;
  };
  const firstReference = checkpoint.event_refs[0];
  assert.ok(firstReference);
  firstReference.event_id = "urn:uuid:00000000-0000-4000-8000-000000000001";

  assert.equal(schemas.validate("event", invalidEvent).valid, false);
  assert.equal(schemas.validate("checkpoint", checkpoint).valid, false);
});

test("validates strict evidence objects and rejects unscoped fields", async () => {
  const schemas = await compileLocalSchemas();
  const valid = JSON.parse(
    await readFile(
      resolve(repositoryRoot, "conformance/valid/evidence/unit-test.json"),
      "utf8",
    ),
  ) as unknown;
  const invalid = JSON.parse(
    await readFile(
      resolve(
        repositoryRoot,
        "conformance/invalid/evidence/additional-property.json",
      ),
      "utf8",
    ),
  ) as unknown;

  assert.equal(schemas.validate("evidence", valid).valid, true);
  assert.equal(schemas.validate("evidence", invalid).valid, false);
});

test("detects digest-consistent evidence identity substitution independently", async () => {
  const vector = JSON.parse(
    await readFile(
      resolve(
        repositoryRoot,
        "conformance/malicious/evidence-identity-substitution.json",
      ),
      "utf8",
    ),
  ) as {
    checkpoint_evidence: CheckpointEvidence;
    evidence_entry: EvidenceObject;
    expected_issue: string;
  };
  const bytes = canonicalJsonBytes(vector.evidence_entry);
  const source = vector.checkpoint_evidence.source;
  assert.ok(source);
  assert.equal(sha256(bytes), source.digest);
  const descriptor: ArchiveEntry = {
    path: source.path,
    media_type: "application/json",
    role: "evidence",
    byte_length: bytes.byteLength,
    digest: source.digest,
  };

  assert.throws(
    () =>
      verifyEvidenceReference(
        vector.checkpoint_evidence,
        vector.evidence_entry,
        descriptor,
        bytes,
      ),
    (error: unknown) =>
      error instanceof ConformanceFailure &&
      error.rule === "evidence-reference-identity" &&
      vector.expected_issue === "reference_identity_mismatch",
  );
});

test("uses full date-time validation rather than accepting impossible calendar dates", async () => {
  const schemas = await compileLocalSchemas();
  const fixture = await loadGoldenFixture();
  const invalidManifest = structuredClone(fixture.manifest) as Record<
    string,
    unknown
  >;
  invalidManifest.created_at = "2026-02-29T08:15:00Z";

  const result = schemas.validate("archiveManifest", invalidManifest);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.keyword === "format"));
});

test("matches every signed entry's exact byte length, digest, and aggregate limits", async () => {
  const fixture = await loadGoldenFixture();
  const report = verifyEntryIntegrity(fixture);

  assert.deepEqual(report, {
    checkedEntries: 3,
    expandedBytes: 2985,
    maxEntryBytes: 1499,
  });
});

test("reconstructs the RFC 8785 projection and verifies payload digest and Ed25519 signature", async () => {
  const fixture = await loadGoldenFixture();
  const projection = manifestSigningProjection(fixture.manifest);
  const projectedSignature = projection.signature as Record<string, unknown>;
  const report = verifyManifestSignature(fixture.manifest);

  assert.equal("payload_digest" in projectedSignature, false);
  assert.equal("value" in projectedSignature, false);
  assert.equal(
    projectedSignature.public_key,
    fixture.manifest.signature.public_key,
  );
  assert.equal(
    report.payloadDigest,
    "sha256:08e30e238d4530044e68a6d6ad88338c681d8d68bfe37f077227b22a7aa17de3",
  );
  assert.equal(report.signatureValid, true);
  assert.ok(report.canonicalBytes.byteLength > 0);
});

test("resolves the root checkpoint, event, and Git-state references and validates inline payload bytes", async () => {
  const fixture = await loadGoldenFixture();
  const references = resolveGoldenReferences(fixture);
  const inlineDigest = verifyInlinePayloadDigest(fixture.event);

  assert.deepEqual(references, {
    rootCheckpointPath: "checkpoints/checkpoint.json",
    eventPaths: ["events/session-started.json"],
    gitStatePath: "state/git-state.json",
    artifactPaths: [],
    evidencePaths: [],
  });
  assert.equal(
    inlineDigest,
    "sha256:2fec874ba561b245ebdde94a7c83705585af5ca76cf6599c07e9ba98f4f0a1da",
  );
});

test("rejects the complete unsafe archive-path matrix in code and schema", async (t) => {
  const schemas = await compileLocalSchemas();
  const fixture = await loadGoldenFixture();
  const unsafePaths = [
    "",
    "/absolute.json",
    "C:/absolute.json",
    "../outside.json",
    "events/../outside.json",
    "events/./outside.json",
    "events//outside.json",
    "events\\outside.json",
    "events/outside.json/",
    "events/\u0000outside.json",
    ".",
    "..",
    "a".repeat(1025),
  ] as const;

  for (const unsafePath of unsafePaths) {
    await t.test(JSON.stringify(unsafePath), () => {
      assert.equal(checkArchivePath(unsafePath), false);
      const manifest = structuredClone(fixture.manifest);
      const first = manifest.entries[0];
      assert.ok(first);
      (first as { path: string }).path = unsafePath;
      assert.equal(schemas.validate("archiveManifest", manifest).valid, false);
    });
  }

  for (const safePath of [
    "events/session-started.json",
    "state/git_state-01.json",
    "artifact.txt",
  ]) {
    assert.equal(checkArchivePath(safePath), true);
  }
});

test("accepts a checkpoint containing a non-empty artifact object", async () => {
  const schemas = await compileLocalSchemas();
  const fixture = await loadGoldenFixture();
  const checkpoint = structuredClone(fixture.checkpoint) as Record<
    string,
    unknown
  >;
  checkpoint.artifacts = [
    {
      path: "artifacts/status.txt",
      digest:
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      media_type: "text/plain",
      role: "status-output",
      byte_length: 17,
    },
  ];

  assert.equal(schemas.validate("checkpoint", checkpoint).valid, true);
});

test("runs the complete golden conformance path without process cwd assumptions", async () => {
  const report = await verifyGoldenConformance(repositoryRoot);

  assert.deepEqual(
    [...report.schemaNames].sort(),
    Object.keys(schemaFiles).sort(),
  );
  assert.equal(report.entries.checkedEntries, 3);
  assert.equal(report.signature.signatureValid, true);
  assert.equal(report.references.eventPaths.length, 1);
});
