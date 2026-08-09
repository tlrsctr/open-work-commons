import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ArchiveInputError,
  type ArchiveExclusion,
  canonicalJsonBytes,
  canonicalizeJson,
  createSignedArchive,
  generateArchiveSigningKey,
  isSafeArchivePath,
  parseJsonSafely,
  SafeJsonError,
  sha256,
  verifyLogicalArchive,
  type GeneratedSigningKey,
  type ArchiveEntryInput,
  type LogicalArchive,
  type VerificationIssueCode,
} from "./index.js";
import { compileLocalSchemas } from "../../../conformance/harness/src/harness.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

test("verifies the published RFC 8785 and Ed25519 fixture offline", () => {
  const archive = loadPublishedFixture();
  const untrusted = verifyLogicalArchive(archive);

  assert.equal(untrusted.integrity.valid, true);
  assert.equal(untrusted.signer.signatureValid, true);
  assert.equal(untrusted.signer.trust, "not-configured");
  assert.equal(untrusted.signer.trusted, false);
  assert.equal(
    untrusted.signer.fingerprint,
    "sha256:eff4aaebfeb39519574246101932daf3751a90be679a4bd0caf07bbedf3c8b74",
  );
  assert.equal(
    untrusted.archive.payloadDigest,
    "sha256:08e30e238d4530044e68a6d6ad88338c681d8d68bfe37f077227b22a7aa17de3",
  );
  assert.deepEqual(untrusted.externalRepositoryVerification, {
    status: "not-checked",
  });

  const trusted = verifyLogicalArchive(archive, {
    trustedSignerFingerprints: [untrusted.signer.fingerprint!],
  });
  assert.equal(trusted.integrity.valid, true);
  assert.equal(trusted.signer.trust, "trusted");
  assert.equal(trusted.signer.trusted, true);
});

test("constructs a deterministic signed archive and sorts entry paths", () => {
  const key = generateArchiveSigningKey("urn:owc:key:test:operator");
  const first = makeArchive(key);
  const second = makeArchive(key);

  assert.deepEqual(first.manifestBytes, second.manifestBytes);
  assert.deepEqual(
    first.entries.map((entry) => entry.path),
    [
      "checkpoints/root.json",
      "events/session-started.json",
      "state/git-state.json",
    ],
  );
  const verified = verifyLogicalArchive(first, {
    trustedSignerFingerprints: [key.fingerprint],
  });
  assert.equal(verified.integrity.valid, true);
  assert.equal(verified.signer.signatureValid, true);
  assert.equal(verified.signer.trusted, true);
});

test("accepts exactly the core event vocabulary or a reverse-DNS extension", async () => {
  const coreTypes = [
    "session.started",
    "context.declared",
    "tool.observed",
    "artifact.changed",
    "evidence.observed",
    "human.intervened",
    "checkpoint.requested",
    "session.ended",
  ] as const;
  for (const eventType of coreTypes) {
    assert.equal(
      verifyLogicalArchive(makeArchive(undefined, undefined, { eventType }))
        .integrity.valid,
      true,
    );
  }
  assert.equal(
    verifyLogicalArchive(
      makeArchive(undefined, undefined, {
        eventType: "org.openworkcommons.fixture/session.annotated",
      }),
    ).integrity.valid,
    true,
  );
  for (const eventType of [
    "session.paused",
    "example/session.paused",
    "org.example/session",
    "Org.example/session.paused",
  ]) {
    assert.throws(
      () => makeArchive(undefined, undefined, { eventType }),
      archiveError("entry_schema_invalid"),
    );
  }

  const schemas = await compileLocalSchemas();
  const event = JSON.parse(
    readFileSync(
      join(
        repositoryRoot,
        "conformance/valid/minimal/events/session-started.json",
      ),
      "utf8",
    ),
  ) as Record<string, unknown>;
  assert.equal(
    schemas.validate("event", { ...event, event_type: "session.paused" }).valid,
    false,
  );
  assert.equal(
    schemas.validate("event", {
      ...event,
      event_type: "org.example/session.paused",
    }).valid,
    true,
  );
});

test("validates evidence entries and binds optional checkpoint sources by identity", () => {
  const evidenceObject = {
    schema_version: "0.1",
    evidence_id: "urn:owc:evidence:test-001",
    kind: "unit-test",
    issuer: "urn:owc:verifier:node-test-runner",
    subject_digest: `sha256:${"3".repeat(64)}`,
    result: "passed",
    observed_at: "2026-08-07T08:09:00Z",
  } as const;
  const evidencePath = "evidence/unit-test.json";
  const evidenceDigest = sha256(canonicalJsonBytes(evidenceObject));
  const checkpointEvidence = {
    evidence_id: evidenceObject.evidence_id,
    kind: evidenceObject.kind,
    issuer: evidenceObject.issuer,
    subject_digest: evidenceObject.subject_digest,
    result: evidenceObject.result,
    observed_at: evidenceObject.observed_at,
    source: { path: evidencePath, digest: evidenceDigest },
  } as const;
  const entry = {
    path: evidencePath,
    mediaType: "application/json",
    role: "evidence",
    json: evidenceObject,
  } as const;

  const linked = makeArchive(undefined, undefined, {
    checkpointEvidence: [checkpointEvidence],
    additionalEntries: [entry],
  });
  assert.equal(verifyLogicalArchive(linked).integrity.valid, true);
  assert.equal(
    verifyLogicalArchive(
      makeArchive(undefined, undefined, {
        checkpointEvidence: [
          {
            evidence_id: checkpointEvidence.evidence_id,
            kind: checkpointEvidence.kind,
            issuer: checkpointEvidence.issuer,
            subject_digest: checkpointEvidence.subject_digest,
            result: checkpointEvidence.result,
            observed_at: checkpointEvidence.observed_at,
          },
        ],
        additionalEntries: [entry],
      }),
    ).integrity.valid,
    true,
  );

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        checkpointEvidence: [
          {
            ...checkpointEvidence,
            issuer: "OWC_ATTACKER_CONTROLLED_ISSUER",
          },
        ],
        additionalEntries: [entry],
      }),
    (error: unknown) =>
      error instanceof ArchiveInputError &&
      error.code === "reference_identity_mismatch" &&
      !error.message.includes("OWC_ATTACKER_CONTROLLED_ISSUER"),
  );
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        checkpointEvidence: [
          {
            ...checkpointEvidence,
            source: {
              path: evidencePath,
              digest: `sha256:${"f".repeat(64)}`,
            },
          },
        ],
        additionalEntries: [entry],
      }),
    archiveError("reference_digest_mismatch"),
  );
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        checkpointEvidence: [checkpointEvidence],
        additionalEntries: [{ ...entry, role: "artifact" }],
      }),
    archiveError("reference_missing"),
  );
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        additionalEntries: [
          {
            ...entry,
            json: { ...evidenceObject, unexpected: true },
          },
        ],
      }),
    archiveError("entry_schema_invalid"),
  );
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        additionalEntries: [{ ...entry, mediaType: "text/plain" }],
      }),
    archiveError("entry_schema_invalid"),
  );
});

test("verifies manifest-only and included untracked files in distinct path namespaces", () => {
  const bytes = Buffer.from("authorized untracked bytes\n", "utf8");
  const contentDigest = sha256(bytes);
  const declaration = {
    path: "notes/todo.txt",
    digest: contentDigest,
    byte_length: bytes.byteLength,
  } as const;

  const manifestOnly = makeArchive(undefined, undefined, {
    worktree: {
      clean: false,
      untracked: [{ ...declaration, included: false }],
    },
  });
  assert.equal(verifyLogicalArchive(manifestOnly).integrity.valid, true);
  const manifestOnlyPaths = JSON.parse(
    new TextDecoder().decode(manifestOnly.manifestBytes),
  ).entries.map((entry: { path: string }) => entry.path) as string[];
  assert.equal(manifestOnlyPaths.includes("notes/todo.txt"), false);

  const artifactPath = "artifacts/git/untracked/notes/todo.txt";
  const included = makeArchive(undefined, undefined, {
    worktree: {
      clean: false,
      untracked: [
        {
          ...declaration,
          included: true,
          artifact: {
            path: artifactPath,
            digest: contentDigest,
            byte_length: bytes.byteLength,
          },
        },
      ],
    },
    additionalEntries: [
      {
        path: artifactPath,
        mediaType: "application/octet-stream",
        role: "artifact",
        bytes,
      },
    ],
  });
  const verified = verifyLogicalArchive(included);
  assert.equal(verified.integrity.valid, true);
  assert.equal(
    included.entries.some((entry) => entry.path === "notes/todo.txt"),
    false,
  );
  assert.equal(
    included.entries.some((entry) => entry.path === artifactPath),
    true,
  );
});

test("fails closed on incoherent untracked inclusion records", () => {
  const bytes = Buffer.from("included\n", "utf8");
  const digest = sha256(bytes);
  const artifact = {
    path: "artifacts/git/untracked/included.txt",
    digest,
    byte_length: bytes.byteLength,
  } as const;

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        worktree: {
          clean: false,
          untracked: [
            {
              path: "included.txt",
              included: true,
              digest,
              byte_length: bytes.byteLength,
            },
          ],
        },
      }),
    archiveError("entry_schema_invalid"),
  );

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        worktree: {
          clean: false,
          untracked: [
            {
              path: "included.txt",
              included: true,
              digest,
              byte_length: bytes.byteLength,
              artifact,
            },
          ],
        },
      }),
    archiveError("reference_missing"),
  );

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        worktree: {
          clean: false,
          untracked: [
            {
              path: "included.txt",
              included: false,
              digest,
              byte_length: bytes.byteLength,
              artifact,
            },
          ],
        },
      }),
    archiveError("entry_schema_invalid"),
  );

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        worktree: {
          clean: false,
          untracked: [
            {
              path: "included.txt",
              included: true,
              digest,
              byte_length: bytes.byteLength,
              artifact: { ...artifact, path: "included.txt" },
            },
          ],
        },
        additionalEntries: [
          {
            path: "included.txt",
            mediaType: "application/octet-stream",
            role: "artifact",
            bytes,
          },
        ],
      }),
    archiveError("entry_schema_invalid"),
  );

  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        worktree: {
          clean: false,
          untracked: [
            {
              path: "z.txt",
              included: false,
              digest,
              byte_length: bytes.byteLength,
            },
            {
              path: "a.txt",
              included: false,
              digest,
              byte_length: bytes.byteLength,
            },
          ],
        },
      }),
    archiveError("entry_schema_invalid"),
  );
});

test("accepts real leap days and rejects normalized impossible calendar dates", () => {
  assert.doesNotThrow(() =>
    makeArchive(undefined, undefined, {
      manifestCreatedAt: "2024-02-29T23:59:59Z",
    }),
  );
  assert.doesNotThrow(() =>
    makeArchive(undefined, undefined, {
      manifestCreatedAt: "2024-12-31T23:59:60Z",
    }),
  );
  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2024-04-31T12:00:00Z",
    "2026-13-01T12:00:00Z",
    "2026-01-01T24:59:00+01:00",
    "2026-01-01T23:59:61Z",
    "2026-01-01T12:00:00+24:00",
  ]) {
    assert.throws(
      () =>
        makeArchive(undefined, undefined, {
          manifestCreatedAt: impossible,
        }),
      archiveError("manifest_schema_invalid"),
    );
  }
});

test("enforces the Git clean-state invariant in the verifier and schema oracle", async () => {
  const digest = `sha256:${"4".repeat(64)}`;
  const invalidWorktrees = [
    {
      clean: true,
      untracked: [
        {
          path: "dirty.txt",
          included: false,
          digest,
          byte_length: 1,
        },
      ],
    },
    { clean: false, untracked: [] },
  ];
  const schemas = await compileLocalSchemas();
  const fixture = JSON.parse(
    readFileSync(
      join(repositoryRoot, "conformance/valid/minimal/state/git-state.json"),
      "utf8",
    ),
  ) as Record<string, unknown>;

  for (const worktree of invalidWorktrees) {
    assert.throws(
      () => makeArchive(undefined, undefined, { worktree }),
      archiveError("entry_schema_invalid"),
    );
    assert.equal(
      schemas.validate("gitState", { ...fixture, worktree }).valid,
      false,
    );
  }
});

test("requires a raw-transcript exclusion in manifests and checkpoints", async () => {
  const nonTranscriptExclusions: readonly ArchiveExclusion[] = [
    {
      category: "temporary-files",
      reason: "Temporary files were omitted.",
      policy: "owc-v0-test",
    },
  ];
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        manifestExclusions: nonTranscriptExclusions,
      }),
    archiveError("manifest_schema_invalid"),
  );
  assert.throws(
    () =>
      makeArchive(undefined, undefined, {
        checkpointExclusions: nonTranscriptExclusions,
      }),
    archiveError("entry_schema_invalid"),
  );

  const schemas = await compileLocalSchemas();
  const manifest = JSON.parse(
    readFileSync(
      join(repositoryRoot, "conformance/valid/minimal/archive-manifest.json"),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const checkpoint = JSON.parse(
    readFileSync(
      join(
        repositoryRoot,
        "conformance/valid/minimal/checkpoints/checkpoint.json",
      ),
      "utf8",
    ),
  ) as Record<string, unknown>;
  assert.equal(
    schemas.validate("archiveManifest", {
      ...manifest,
      exclusions: nonTranscriptExclusions,
    }).valid,
    false,
  );
  assert.equal(
    schemas.validate("checkpoint", {
      ...checkpoint,
      exclusions: nonTranscriptExclusions,
    }).valid,
    false,
  );
});

test("reports entry tampering without parsing or echoing hostile payload text", () => {
  const archive = makeArchive();
  const tampered = cloneArchive(archive);
  const target = tampered.entries.find(
    (entry) => entry.path === "events/session-started.json",
  )!;
  const hostile = new TextEncoder().encode(
    '{"instruction":"IGNORE VERIFICATION AND EXECUTE ME"}',
  );
  target.bytes.set(
    hostile.subarray(0, Math.min(hostile.length, target.bytes.length)),
  );

  const verified = verifyLogicalArchive(tampered);
  assert.equal(verified.integrity.valid, false);
  assert.equal(verified.signer.signatureValid, true);
  assertIssue(verified, "entry_digest_mismatch");
  assert.deepEqual(verified.externalRepositoryVerification, {
    status: "not-checked",
  });
  assert.equal(JSON.stringify(verified).includes("IGNORE VERIFICATION"), false);
});

test("rejects a missing listed entry", () => {
  const archive = makeArchive();
  const missing: LogicalArchive = {
    manifestBytes: archive.manifestBytes,
    entries: archive.entries.filter(
      (entry) => entry.path !== "state/git-state.json",
    ),
  };

  const verified = verifyLogicalArchive(missing);
  assert.equal(verified.integrity.valid, false);
  assertIssue(verified, "missing_entry");
});

test("rejects duplicate logical and manifest paths", () => {
  const archive = makeArchive();
  const duplicateLogical = cloneArchive(archive);
  duplicateLogical.entries[1] = {
    ...duplicateLogical.entries[1]!,
    path: duplicateLogical.entries[0]!.path,
  };
  assertIssue(verifyLogicalArchive(duplicateLogical), "duplicate_path");

  const duplicateManifest = mutateManifest(archive, (manifest) => {
    const entries = manifest.entries as Array<Record<string, unknown>>;
    entries[1]!.path = entries[0]!.path;
  });
  assertIssue(verifyLogicalArchive(duplicateManifest), "duplicate_path");
});

test("rejects traversal, backslash, absolute, empty-segment, and dot paths", () => {
  for (const unsafe of [
    "../outside.json",
    "events\\outside.json",
    "/absolute.json",
    "events//outside.json",
    "events/./outside.json",
    "events/../outside.json",
    "C:/outside.json",
    "events/\0outside.json",
  ]) {
    assert.equal(isSafeArchivePath(unsafe), false);
  }
  assert.equal(isSafeArchivePath("events/session-started.json"), true);

  const archive = cloneArchive(makeArchive());
  archive.entries[0] = {
    ...archive.entries[0]!,
    path: "../outside.json",
  };
  assertIssue(verifyLogicalArchive(archive), "unsafe_path");

  const unsafeManifest = mutateManifest(makeArchive(), (manifest) => {
    const entries = manifest.entries as Array<Record<string, unknown>>;
    entries[0]!.path = "../outside.json";
  });
  assertIssue(verifyLogicalArchive(unsafeManifest), "unsafe_path");
});

test("enforces independent byte, expanded-byte, and entry-count limits", () => {
  const archive = makeArchive();
  const largest = Math.max(
    ...archive.entries.map((entry) => entry.bytes.length),
  );
  const total = archive.entries.reduce(
    (sum, entry) => sum + entry.bytes.length,
    0,
  );

  assertIssue(
    verifyLogicalArchive(archive, { limits: { maxEntryBytes: largest - 1 } }),
    "entry_bytes_limit",
  );
  assertIssue(
    verifyLogicalArchive(archive, {
      limits: { maxExpandedBytes: total - 1 },
    }),
    "expanded_bytes_limit",
  );
  assertIssue(
    verifyLogicalArchive(archive, { limits: { maxEntryCount: 2 } }),
    "entry_count_limit",
  );
});

test("keeps cryptographic integrity separate from local signer trust", () => {
  const operator = generateArchiveSigningKey("urn:owc:key:test:operator");
  const attacker = generateArchiveSigningKey("urn:owc:key:test:attacker");
  const substituted = makeArchive(attacker);

  const verified = verifyLogicalArchive(substituted, {
    trustedSignerFingerprints: [operator.fingerprint],
  });
  assert.equal(verified.integrity.valid, true);
  assert.equal(verified.signer.signatureValid, true);
  assert.equal(verified.signer.trust, "untrusted");
  assert.equal(verified.signer.trusted, false);
  assert.equal(verified.signer.fingerprint, attacker.fingerprint);

  const keyChangedWithoutResigning = mutateManifest(
    makeArchive(operator),
    (manifest) => {
      const signature = manifest.signature as Record<string, unknown>;
      signature.public_key = attacker.publicKeyBase64Url;
    },
  );
  const invalid = verifyLogicalArchive(keyChangedWithoutResigning, {
    trustedSignerFingerprints: [operator.fingerprint],
  });
  assert.equal(invalid.integrity.valid, false);
  assert.equal(invalid.signer.signatureValid, false);
  assertIssue(invalid, "signature_invalid");
});

test("rejects duplicate manifest JSON keys before schema or signature checks", () => {
  const archive = makeArchive();
  const text = new TextDecoder().decode(archive.manifestBytes);
  const duplicated = text.replace(
    '"archive_id":',
    '"archive_id":"urn:owc:archive:duplicate","archive_id":',
  );
  const verified = verifyLogicalArchive({
    manifestBytes: new TextEncoder().encode(duplicated),
    entries: archive.entries,
  });
  assert.equal(verified.integrity.valid, false);
  assertIssue(verified, "manifest_duplicate_json_key");
  assert.equal(verified.signer.signatureValid, false);
});

test("rejects special entries before dereferencing or inspecting their bytes", () => {
  const archive = cloneArchive(makeArchive());
  archive.entries[0] = { ...archive.entries[0]!, kind: "symlink" };
  const verified = verifyLogicalArchive(archive);
  assert.equal(verified.integrity.valid, false);
  assertIssue(verified, "special_entry");
});

test("strict JSON parsing rejects duplicate keys, deep nesting, and lone surrogates", () => {
  assert.throws(
    () =>
      parseJsonSafely(new TextEncoder().encode('{"a":1,"a":2}'), {
        maxDepth: 8,
        maxStringBytes: 64,
      }),
    (error) => error instanceof SafeJsonError && error.kind === "duplicate-key",
  );
  assert.throws(
    () =>
      parseJsonSafely(new TextEncoder().encode("[[[0]]]"), {
        maxDepth: 2,
        maxStringBytes: 64,
      }),
    (error) =>
      error instanceof SafeJsonError && error.kind === "resource-limit",
  );
  assert.throws(
    () =>
      parseJsonSafely(new TextEncoder().encode('"\\ud800"'), {
        maxDepth: 8,
        maxStringBytes: 64,
      }),
    (error) => error instanceof SafeJsonError && error.kind === "syntax",
  );
});

test("canonical JSON follows RFC 8785 ordering and number/string rules", () => {
  assert.equal(
    canonicalizeJson({
      "😀": "emoji",
      z: -0,
      "€": "euro",
      a: [333333333.33333329, 1e30, 4.5, 0.002, 1e-27, "\u000f\n"],
    }),
    '{"a":[333333333.3333333,1e+30,4.5,0.002,1e-27,"\\u000f\\n"],"z":0,"€":"euro","😀":"emoji"}',
  );
  assert.throws(() => canonicalizeJson(Number.NaN), TypeError);
  assert.throws(() => canonicalizeJson("\ud800"), TypeError);
  const accessor = Object.defineProperty({}, "value", {
    enumerable: true,
    get: () => "must-not-run",
  });
  assert.throws(() => canonicalizeJson(accessor), TypeError);
});

test("constructor fails closed on a malformed root checkpoint", () => {
  assert.throws(
    () => makeArchive(undefined, "urn:owc:checkpoint:not-the-entry"),
    (error) =>
      error instanceof ArchiveInputError &&
      error.code === "reference_identity_mismatch",
  );
});

function makeArchive(
  suppliedKey?: GeneratedSigningKey,
  rootCheckpointId = "urn:owc:checkpoint:test-001",
  options: {
    readonly eventType?: string;
    readonly manifestCreatedAt?: string;
    readonly worktree?: unknown;
    readonly additionalEntries?: readonly ArchiveEntryInput[];
    readonly checkpointEvidence?: readonly unknown[];
    readonly manifestExclusions?: readonly ArchiveExclusion[];
    readonly checkpointExclusions?: readonly ArchiveExclusion[];
  } = {},
): LogicalArchive {
  const key = suppliedKey ?? generateArchiveSigningKey("urn:owc:key:test");
  const inlinePayload = {
    objective: "Build a bounded offline archive verifier.",
  };
  const event = {
    schema_version: "0.1",
    event_id: "urn:owc:event:test-session-started-001",
    event_type: options.eventType ?? "session.started",
    recorded_at: "2026-08-07T08:00:00Z",
    actor: { id: "urn:owc:actor:test", kind: "human" },
    space_id: "urn:owc:space:test",
    session_id: "urn:owc:session:test-001",
    sequence: 0,
    previous_event_id: null,
    provider: { name: "entire", adapter_version: "0.9.0" },
    subject: { kind: "session", id: "urn:owc:session:test-001" },
    payload: {
      media_type: "application/json",
      digest: sha256(canonicalJsonBytes(inlinePayload)),
      inline: inlinePayload,
    },
    sensitivity: "private",
    retention: { class: "checkpoint", expires_at: null },
  };
  const gitState = {
    schema_version: "0.1",
    repository_id: "urn:owc:repository:test",
    object_format: "sha1",
    captured_at: "2026-08-07T08:05:00Z",
    base_commit: "1".repeat(40),
    head_commit: "2".repeat(40),
    head_tree: "3".repeat(40),
    head_ref: "refs/heads/main",
    worktree: options.worktree ?? { clean: true, untracked: [] },
  };
  const eventDigest = sha256(canonicalJsonBytes(event));
  const gitStateDigest = sha256(canonicalJsonBytes(gitState));
  const defaultExclusions: readonly ArchiveExclusion[] = [
    {
      category: "raw-transcript",
      reason: "Raw transcripts are excluded by default.",
      policy: "owc-v0-default-private",
    },
  ];
  const checkpoint = {
    schema_version: "0.1",
    checkpoint_id: "urn:owc:checkpoint:test-001",
    created_at: "2026-08-07T08:10:00Z",
    session_id: "urn:owc:session:test-001",
    capture_providers: [{ name: "entire" }],
    work: {
      work_item_id: "OWC-TEST-1",
      title: "Offline archive verification",
      objective: "Build a bounded offline archive verifier.",
      constraints: ["No verification network access."],
    },
    parents: [],
    event_refs: [
      {
        event_id: event.event_id,
        path: "events/session-started.json",
        digest: eventDigest,
      },
    ],
    git_state: {
      path: "state/git-state.json",
      digest: gitStateDigest,
    },
    artifacts: [],
    claims: [],
    evidence: options.checkpointEvidence ?? [],
    open_questions: [],
    exclusions: options.checkpointExclusions ?? defaultExclusions,
    next_action: {
      statement: "Verify the archive on a second machine.",
      source_paths: ["events/session-started.json", "state/git-state.json"],
    },
  };

  return createSignedArchive({
    archiveId: "urn:owc:archive:test-001",
    createdAt: options.manifestCreatedAt ?? "2026-08-07T08:15:00Z",
    rootCheckpoint: {
      checkpointId: rootCheckpointId,
      path: "checkpoints/root.json",
    },
    // Deliberately unsorted: the writer owns deterministic path ordering.
    entries: [
      {
        path: "state/git-state.json",
        mediaType: "application/json",
        role: "git-state",
        json: gitState,
      },
      {
        path: "events/session-started.json",
        mediaType: "application/json",
        role: "event",
        json: event,
      },
      {
        path: "checkpoints/root.json",
        mediaType: "application/json",
        role: "checkpoint",
        json: checkpoint,
      },
      ...(options.additionalEntries ?? []),
    ],
    exclusions: options.manifestExclusions ?? defaultExclusions,
    signingKey: { keyId: key.keyId, privateKey: key.privateKey },
  });
}

function archiveError(
  code: VerificationIssueCode,
): (error: unknown) => boolean {
  return (error) => error instanceof ArchiveInputError && error.code === code;
}

function loadPublishedFixture(): LogicalArchive {
  const base = join(repositoryRoot, "conformance/valid/minimal");
  return {
    manifestBytes: readFileSync(join(base, "archive-manifest.json")),
    entries: [
      "checkpoints/checkpoint.json",
      "events/session-started.json",
      "state/git-state.json",
    ].map((path) => ({ path, bytes: readFileSync(join(base, path)) })),
  };
}

function cloneArchive(archive: LogicalArchive): {
  manifestBytes: Uint8Array;
  entries: Array<{ path: string; bytes: Uint8Array; kind?: string }>;
} {
  return {
    manifestBytes: Uint8Array.from(archive.manifestBytes),
    entries: archive.entries.map((entry) => ({
      path: entry.path,
      bytes: Uint8Array.from(entry.bytes),
      ...(entry.kind === undefined ? {} : { kind: entry.kind }),
    })),
  };
}

function mutateManifest(
  archive: LogicalArchive,
  mutate: (manifest: Record<string, unknown>) => void,
): LogicalArchive {
  const manifest = JSON.parse(
    new TextDecoder().decode(archive.manifestBytes),
  ) as Record<string, unknown>;
  mutate(manifest);
  return {
    manifestBytes: canonicalJsonBytes(manifest),
    entries: archive.entries,
  };
}

function assertIssue(
  result: ReturnType<typeof verifyLogicalArchive>,
  code: VerificationIssueCode,
): void {
  assert.equal(
    result.integrity.issues.some((issue) => issue.code === code),
    true,
    `Expected verification issue ${code}; got ${result.integrity.issues
      .map((issue) => issue.code)
      .join(", ")}`,
  );
}
