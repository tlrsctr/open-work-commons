import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalJsonBytes,
  createSignedArchive as signArchive,
  generateArchiveSigningKey,
  sha256,
  type GeneratedSigningKey,
  type LogicalArchive,
} from "../../archive/src/index.js";
import type {
  CapturedGitState,
  GitStateV0,
} from "../../git-state/src/index.js";
import type {
  DeviceSigningIdentity,
  PublicDeviceIdentity,
  UnsignedArchiveInput,
} from "../../identity/src/index.js";
import { compileResumeBundle } from "../../resume/src/index.js";
import { LocalWorkspaceStore } from "../../store/src/index.js";
import { compileLocalSchemas } from "../../../conformance/harness/src/harness.js";

import {
  createApprovedHandoff,
  createExactHandoffStorePolicy,
  HandoffError,
  inspectHandoff,
  persistApprovedHandoff,
  type HandoffInspection,
  type HandoffStoreWritePlan,
  type InspectHandoffInput,
  type OperatorHandoffPlan,
} from "./index.js";

const CAPTURED_AT = "2026-08-07T12:00:00Z";
const EXTERNAL_CHECKPOINT_ID = "01KVBJCWYA4YW6J5M9GP655HZN";
test("inspection is deterministic, reviewable, excludes provider prose, and never signs", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const first = inspectHandoff(input);
  const second = inspectHandoff(input);

  assert.deepEqual(first, second);
  assert.match(first.approvalDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(identity.signCalls, 0);
  assert.equal(identity.archiveCalls, 0);
  assert.deepEqual(
    first.included.events.map((event) => event.event_type),
    ["human.intervened", "human.intervened", "checkpoint.requested"],
  );
  assert.equal(first.included.checkpoint.claims.length, 0);
  assert.equal(first.included.checkpoint.evidence.length, 0);
  assert.equal(first.included.artifacts.length, 1);
  assert.equal(first.included.providerProjection.sessions.length, 1);
  assert.ok(first.gaps.imported.includes("event_history_unavailable"));
  assert.ok(
    first.gaps.resolvedByExactApproval.includes(
      "authorization_and_redaction_required",
    ),
  );
  assert.equal(first.gaps.blocking.length, 0);

  const reviewText = JSON.stringify(first);
  for (const canary of [
    "TRANSCRIPT_CANARY",
    "PROMPT_CANARY",
    "RESPONSE_CANARY",
    "SUMMARY_CANARY",
    "MESSAGE_CANARY",
    "UNKNOWN_CANARY",
    "FILE_CANARY",
  ]) {
    assert.equal(reviewText.includes(canary), false);
  }
  assert.deepEqual(Object.keys(first.included.providerProjection).sort(), [
    "external_session_ids",
    "format",
    "handling",
    "imported_gaps",
    "provider_timestamp",
    "schema_version",
    "sessions",
    "source",
  ]);
});

test("strict plans reject unknown keys, unsafe values, bad time, and provider mismatch", () => {
  const identity = new CountingIdentity();
  const base = makeInput(identity);
  assert.throws(
    () =>
      inspectHandoff({
        ...base,
        plan: {
          ...base.plan,
          transcript: "must-not-exist",
        } as OperatorHandoffPlan,
      }),
    hasCode("invalid_plan"),
  );
  assert.throws(
    () =>
      inspectHandoff({
        ...base,
        plan: { ...base.plan, nextAction: "unsafe\ncommand" },
      }),
    hasCode("invalid_plan"),
  );
  assert.throws(
    () =>
      inspectHandoff({
        ...base,
        plan: { ...base.plan, actor: { id: "unsafe/actor" } },
      }),
    hasCode("invalid_plan"),
  );
  assert.throws(
    () => inspectHandoff({ ...base, capturedAt: "2026-02-31T00:00:00Z" }),
    hasCode("invalid_input"),
  );
  assert.throws(
    () =>
      inspectHandoff({
        ...base,
        plan: {
          ...base.plan,
          source: { ...base.plan.source, provider: "other" },
        } as unknown as OperatorHandoffPlan,
      }),
    hasCode("provider_mismatch"),
  );
});

test("rejects external checkpoint mismatch and invalid imported detail", () => {
  const identity = new CountingIdentity();
  const base = makeInput(identity);
  assert.throws(
    () =>
      inspectHandoff({
        ...base,
        plan: {
          ...base.plan,
          source: {
            ...base.plan.source,
            externalCheckpointId: "different-checkpoint",
          },
        },
      }),
    hasCode("external_checkpoint_mismatch"),
  );
  assert.throws(
    () => inspectHandoff({ ...base, entireCheckpointDetailJson: "{bad-json" }),
    hasCode("entire_import_invalid"),
  );
});

test("approval is exact and fails before signing on mismatch or Git drift", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);

  assert.throws(
    () =>
      createApprovedHandoff({
        ...input,
        approvalDigest: `sha256:${"f".repeat(64)}`,
      }),
    hasCode("approval_mismatch"),
  );
  assert.equal(identity.archiveCalls, 0);

  const drifted = driftGit(input.git);
  assert.throws(
    () =>
      createApprovedHandoff({
        ...input,
        git: drifted,
        approvalDigest: inspection.approvalDigest,
      }),
    hasCode("approval_mismatch"),
  );
  assert.equal(identity.archiveCalls, 0);
});

test("creates a schema-valid verifiable archive, exact event chain, and resumable bundle", async () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });

  assert.equal(identity.signCalls, 0);
  assert.equal(identity.archiveCalls, 1);
  assert.equal(approved.verification.integrity.valid, true);
  assert.equal(approved.verification.signer.signatureValid, true);
  assert.equal(approved.verification.signer.trusted, true);
  assert.equal(
    approved.verification.archive.payloadDigest,
    inspection.proposedArchive.payloadDigest,
  );
  approved.events.forEach((event, index) => {
    assert.equal(event.sequence, index);
    assert.equal(
      event.previous_event_id,
      index === 0 ? null : approved.events[index - 1]?.event_id,
    );
  });
  assert.equal(approved.events.at(-1)?.event_type, "checkpoint.requested");

  const schemas = await compileLocalSchemas();
  const manifest = JSON.parse(
    new TextDecoder().decode(approved.archive.manifestBytes),
  ) as unknown;
  schemas.assertValid("archiveManifest", manifest);
  schemas.assertValid("checkpoint", approved.checkpoint);
  schemas.assertValid("gitState", input.git.state);
  for (const event of approved.events) schemas.assertValid("event", event);

  const resume = compileResumeBundle({
    archive: approved.archive,
    verification: approved.verification,
    target: "codex",
    budget: { maxItems: 128, maxUtf8Bytes: 65_536 },
  });
  schemas.assertValid("resumeBundle", resume.bundle);
  assert.equal(resume.bundle.objective.statement, input.plan.work.objective);
  assert.deepEqual(
    resume.bundle.decisions.map((decision) => decision.statement),
    input.plan.decisions,
  );
  assert.equal(resume.bundle.next_action.statement, input.plan.nextAction);
  assert.ok(resume.bundle.objective.source_paths.length > 0);
  assert.ok(resume.bundle.next_action.source_paths.length > 0);
});

test("exact store policy denies everything else and persistence replays idempotently", async () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  const policy = createExactHandoffStorePolicy(approved.storeWritePlan);
  const firstBlob = approved.storeWritePlan.blobs[0];
  assert.ok(firstBlob);
  assert.deepEqual(
    await policy.authorizeAndRedactBlob({
      bytes: Buffer.from("not approved"),
      mediaType: firstBlob.mediaType,
    }),
    { decision: "deny" },
  );
  assert.deepEqual(
    await policy.authorizeAndRedactEvent({
      event: { ...approved.events[0], event_id: "urn:owc:event:other" },
    }),
    { decision: "deny" },
  );
  assert.deepEqual(
    await policy.authorizeRead({
      kind: "event",
      eventId: approved.events[0]!.event_id,
    }),
    { decision: "deny" },
  );

  const root = await mkdtemp(join(tmpdir(), "owc-handoff-store-"));
  try {
    const store = await LocalWorkspaceStore.initialize(root, { policy });
    const first = await persistApprovedHandoff(store, approved.storeWritePlan);
    assert.ok(first.blobs.every((item) => item.disposition === "stored"));
    assert.ok(first.events.every((item) => item.disposition === "stored"));

    const replay = await persistApprovedHandoff(store, approved.storeWritePlan);
    assert.ok(replay.blobs.every((item) => item.disposition === "existing"));
    assert.ok(replay.events.every((item) => item.disposition === "existing"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("uses the archive/store RFC 3339 calendar and UTC leap-second policy without Date rollovers", () => {
  const valid = [
    "0000-01-01T00:00:00Z",
    "0001-02-28T00:00:00Z",
    "0096-02-29T23:59:59Z",
    "1900-02-28T00:00:00-23:59",
    "2000-02-29T23:59:59.123456789012+23:59",
    "1990-12-31T23:59:60Z",
    "1990-12-31T12:59:60-11:00",
    "9999-12-31T23:59:59Z",
  ] as const;
  for (const capturedAt of valid) {
    const identity = new CountingIdentity();
    const input = makeInput(identity);
    const variant = { ...input, capturedAt, git: makeGit(capturedAt) };
    const inspection = inspectHandoff(variant);
    const approved = createApprovedHandoff({
      ...variant,
      approvalDigest: inspection.approvalDigest,
    });
    assert.equal(approved.verification.integrity.valid, true);
  }

  const invalid = [
    "0001-02-29T00:00:00Z",
    "0099-02-29T00:00:00Z",
    "1900-02-29T00:00:00Z",
    "2026-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T23:60:00Z",
    "2026-01-01T12:00:60Z",
    "2026-01-01T12:59:60+11:00",
    "2026-01-01T23:59:61Z",
    "2026-01-01T12:00:00+24:00",
    "2026-01-01T12:00:00-00:60",
    "2026-01-01t12:00:00z",
    "2026-01-01 12:00:00Z",
    "2026-01-01T12:00:00+0100",
    `2026-01-01T12:00:00.${"1".repeat(110)}Z`,
  ] as const;
  for (const capturedAt of invalid) {
    const identity = new CountingIdentity();
    const input = makeInput(identity);
    assert.throws(
      () => inspectHandoff({ ...input, capturedAt, git: makeGit(capturedAt) }),
      hasCode("invalid_input"),
    );
  }

  const identity = new CountingIdentity();
  const input = makeInput(identity);
  assert.doesNotThrow(() =>
    inspectHandoff({
      ...input,
      plan: {
        ...input.plan,
        retention: {
          class: "checkpoint",
          expiresAt: "1990-12-31T23:59:60Z",
        },
      },
    }),
  );
  assert.throws(
    () =>
      inspectHandoff({
        ...input,
        plan: {
          ...input.plan,
          retention: {
            class: "checkpoint",
            expiresAt: "2026-01-01T12:00:60Z",
          },
        },
      }),
    hasCode("invalid_plan"),
  );
});

test("strict plan text rejects empty, non-NFC, control, format, bidi, separator, duplicate, and oversized values", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const unsafeNextActions = [
    "",
    "Cafe\u0301",
    "control\u0000character",
    "arabic-mark\u061Cunsafe",
    "override\u202Eunsafe",
    "isolate\u2066unsafe",
    "joiner\u200Dunsafe",
    "separator\u2028unsafe",
  ] as const;
  for (const nextAction of unsafeNextActions) {
    assert.throws(
      () =>
        inspectHandoff({
          ...input,
          plan: { ...input.plan, nextAction },
        }),
      hasCode("invalid_plan"),
    );
  }

  const invalidPlans: readonly OperatorHandoffPlan[] = [
    { ...input.plan, decisions: [""] },
    { ...input.plan, decisions: ["same", "same"] },
    {
      ...input.plan,
      work: { ...input.plan.work, constraints: ["same", "same"] },
    },
    { ...input.plan, openQuestions: ["same", "same"] },
    { ...input.plan, decisions: Array(129).fill("decision") },
    {
      ...input.plan,
      work: {
        ...input.plan.work,
        constraints: Array(129).fill("constraint"),
      },
    },
    { ...input.plan, openQuestions: Array(129).fill("question") },
    {
      ...input.plan,
      work: { ...input.plan.work, title: "é".repeat(257) },
    },
  ];
  for (const plan of invalidPlans) {
    assert.throws(
      () => inspectHandoff({ ...input, plan }),
      hasCode("invalid_plan"),
    );
  }
});

test("zero and multiple decisions have an exact deterministic event boundary", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const zero = inspectHandoff({
    ...input,
    plan: { ...input.plan, decisions: [] },
  });
  assert.deepEqual(
    zero.included.events.map((event) => event.event_type),
    ["checkpoint.requested"],
  );

  const multiple = inspectHandoff({
    ...input,
    plan: { ...input.plan, decisions: ["first", "second", "third"] },
  });
  assert.deepEqual(
    multiple.included.events.map((event) => event.event_type),
    [
      "human.intervened",
      "human.intervened",
      "human.intervened",
      "checkpoint.requested",
    ],
  );
  const reversed = inspectHandoff({
    ...input,
    plan: { ...input.plan, decisions: ["third", "second", "first"] },
  });
  assert.notEqual(multiple.approvalDigest, reversed.approvalDigest);
});

test("approval binds every normative input while excluded provider prose remains deliberately unbound", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const base = inspectHandoff(input);
  const changedArtifact = makeGit(CAPTURED_AT, "ARTIFACT_CHANGED\n");
  const changedCapture = "2026-08-07T12:00:01Z";
  const inputVariants: readonly InspectHandoffInput[] = [
    {
      ...input,
      plan: {
        ...input.plan,
        work: { ...input.plan.work, objective: "A changed objective." },
      },
    },
    {
      ...input,
      plan: { ...input.plan, decisions: ["A changed decision."] },
    },
    {
      ...input,
      plan: { ...input.plan, nextAction: "A changed next action." },
    },
    {
      ...input,
      plan: {
        ...input.plan,
        retention: { class: "archive", expiresAt: null },
      },
    },
    {
      ...input,
      entireCheckpointDetailJson: mutateEntireDetail(
        input.entireCheckpointDetailJson,
        (detail) => {
          const sessions = detail.sessions as Record<string, unknown>[];
          if (sessions[0]) {
            sessions[0].created_at = "2026-08-07T11:56:00Z";
          }
        },
      ),
    },
    {
      ...input,
      entireCheckpointDetailJson: mutateEntireDetail(
        input.entireCheckpointDetailJson,
        (detail) => {
          detail.sessions = [{ index: 0, error: "PROVIDER_ERROR_CANARY" }];
        },
      ),
    },
    { ...input, git: driftGit(input.git) },
    { ...input, git: changedArtifact },
    {
      ...input,
      capturedAt: changedCapture,
      git: makeGit(changedCapture),
    },
  ];
  for (const variant of inputVariants) {
    const changed = inspectHandoff(variant);
    assert.notEqual(changed.approvalDigest, base.approvalDigest);
    assert.throws(
      () =>
        createApprovedHandoff({
          ...variant,
          approvalDigest: base.approvalDigest,
        }),
      hasCode("approval_mismatch"),
    );
  }
  assert.equal(identity.archiveCalls, 0);

  const substitute = new CountingIdentity();
  const substituted = { ...input, signingIdentity: substitute };
  assert.notEqual(
    inspectHandoff(substituted).approvalDigest,
    base.approvalDigest,
  );
  assert.throws(
    () =>
      createApprovedHandoff({
        ...substituted,
        approvalDigest: base.approvalDigest,
      }),
    hasCode("approval_mismatch"),
  );
  assert.equal(substitute.archiveCalls, 0);

  const changedExcludedProse = mutateEntireDetail(
    input.entireCheckpointDetailJson,
    (detail) => {
      detail.message = "DIFFERENT_MESSAGE_CANARY";
      detail.branch = "different/excluded-branch";
      const sessions = detail.sessions as Record<string, unknown>[];
      if (sessions[0]) {
        sessions[0].agent = "DIFFERENT_AGENT_CANARY";
        sessions[0].model = "DIFFERENT_MODEL_CANARY";
        sessions[0].summary = {
          intent: "DIFFERENT_SUMMARY_CANARY",
          outcome: null,
          friction: [],
          open_items: [],
          learnings: { repo: [], code: [], workflow: [] },
        };
      }
    },
  );
  assert.equal(
    inspectHandoff({
      ...input,
      entireCheckpointDetailJson: changedExcludedProse,
    }).approvalDigest,
    base.approvalDigest,
  );

  assert.equal(approvalProjectionDigest(base), base.approvalDigest);
  const changedExclusion = cloneInspection(base);
  const firstExclusion = changedExclusion.excluded[0];
  assert.ok(firstExclusion);
  (firstExclusion as { reason: string }).reason = "changed exclusion";
  assert.notEqual(
    approvalProjectionDigest(changedExclusion),
    base.approvalDigest,
  );
  const changedGap = cloneInspection(base);
  (changedGap.gaps.imported as string[]).push("changed-gap");
  assert.notEqual(approvalProjectionDigest(changedGap), base.approvalDigest);
});

test("inspection exposes review metadata but never raw provider prose, provider errors, input JSON, or Git artifact bytes", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const artifactCanary = "RAW_ARTIFACT_BYTES_CANARY";
  const withProviderError = mutateEntireDetail(
    input.entireCheckpointDetailJson,
    (detail) => {
      detail.sessions = [{ index: 0, error: "PROVIDER_ERROR_PROSE_CANARY" }];
    },
  );
  const inspection = inspectHandoff({
    ...input,
    entireCheckpointDetailJson: withProviderError,
    git: makeGit(CAPTURED_AT, artifactCanary),
  });
  const reviewText = JSON.stringify(inspection);
  for (const canary of [
    "PROVIDER_ERROR_PROSE_CANARY",
    artifactCanary,
    "TRANSCRIPT_CANARY",
    "PROMPT_CANARY",
    "RESPONSE_CANARY",
    "SUMMARY_CANARY",
    "MESSAGE_CANARY",
    "UNKNOWN_CANARY",
    "FILE_CANARY",
  ]) {
    assert.equal(reviewText.includes(canary), false);
  }
  const keys = collectKeys(inspection);
  for (const forbiddenKey of [
    "bytes",
    "stateBytes",
    "patchArtifact",
    "untrackedArtifacts",
    "entireCheckpointDetailJson",
    "raw_transcript",
    "prompts",
    "responses",
    "summary",
    "error",
  ]) {
    assert.equal(keys.has(forbiddenKey), false);
  }
});

test("validates the complete canonical public identity and rejects signer substitution before persistence", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const base = inspectHandoff(input);
  const other = new CountingIdentity();
  const mismatchedSpki = wrapIdentity(identity, {
    ...identity.publicIdentity,
    public_key_spki: other.publicIdentity.public_key_spki,
  });
  assert.throws(
    () => inspectHandoff({ ...input, signingIdentity: mismatchedSpki }),
    hasCode("signing_identity_invalid"),
  );
  const unknownIdentityField = wrapIdentity(identity, {
    ...identity.publicIdentity,
    unexpected: "must-not-be-ignored",
  } as PublicDeviceIdentity);
  assert.throws(
    () => inspectHandoff({ ...input, signingIdentity: unknownIdentityField }),
    hasCode("signing_identity_invalid"),
  );

  const substituting = new SubstitutingIdentity(identity.publicIdentity);
  assert.throws(
    () =>
      createApprovedHandoff({
        ...input,
        signingIdentity: substituting,
        approvalDigest: base.approvalDigest,
      }),
    hasCode("archive_construction_failed"),
  );
  assert.equal(substituting.archiveCalls, 1);
});

test("copies signer-owned archive bytes before verification and store-plan construction", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  const manifestBefore = new Uint8Array(approved.archive.manifestBytes);
  const firstEntryBefore = new Uint8Array(approved.archive.entries[0]!.bytes);
  assert.ok(identity.lastArchive);
  identity.lastArchive.manifestBytes.fill(0);
  identity.lastArchive.entries[0]!.bytes.fill(0);
  assert.deepEqual(approved.archive.manifestBytes, manifestBefore);
  assert.deepEqual(approved.archive.entries[0]!.bytes, firstEntryBefore);
  assert.doesNotThrow(() =>
    createExactHandoffStorePolicy(approved.storeWritePlan),
  );
});

test("exact store policy revalidates the signed archive, clones its capability, and denies every nonapproved operation", async () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  const plan = approved.storeWritePlan;
  const originalFirstBlob = new Uint8Array(plan.blobs[0]!.bytes);
  const policy = createExactHandoffStorePolicy(plan);

  const approvedBlob = plan.blobs[0]!;
  assert.deepEqual(
    await policy.authorizeAndRedactBlob({
      bytes: originalFirstBlob,
      mediaType: approvedBlob.mediaType,
    }),
    { decision: "allow", value: originalFirstBlob },
  );
  assert.deepEqual(
    await policy.authorizeAndRedactBlob({
      bytes: originalFirstBlob,
      mediaType: `${approvedBlob.mediaType};changed=true`,
    }),
    { decision: "deny" },
  );
  const changedBlob = new Uint8Array(originalFirstBlob);
  changedBlob[0] = (changedBlob[0] ?? 0) ^ 1;
  assert.deepEqual(
    await policy.authorizeAndRedactBlob({
      bytes: changedBlob,
      mediaType: approvedBlob.mediaType,
    }),
    { decision: "deny" },
  );
  const approvedEvent = plan.events[0]!;
  assert.equal(
    (await policy.authorizeAndRedactEvent({ event: approvedEvent.event }))
      .decision,
    "allow",
  );
  assert.deepEqual(
    await policy.authorizeAndRedactEvent({
      event: { ...approvedEvent.event, sequence: 999 },
    }),
    { decision: "deny" },
  );
  assert.deepEqual(
    await policy.authorizeRead({ kind: "blob", digest: approvedBlob.digest }),
    { decision: "deny" },
  );
  assert.deepEqual(
    await policy.authorizeRead({
      kind: "event",
      eventId: approvedEvent.eventId,
    }),
    { decision: "deny" },
  );

  plan.blobs[0]!.bytes.fill(0);
  assert.deepEqual(
    await policy.authorizeAndRedactBlob({
      bytes: originalFirstBlob,
      mediaType: approvedBlob.mediaType,
    }),
    { decision: "allow", value: originalFirstBlob },
  );
});

test("tampered, duplicate, and oversized store plans fail before any writer call", async () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  const plan = approved.storeWritePlan;
  const tamperedBytes = cloneStorePlan(plan);
  const target = tamperedBytes.blobs.find(
    (item) => item.archivePath !== "archive-manifest.json",
  );
  assert.ok(target);
  target.bytes[0] = (target.bytes[0] ?? 0) ^ 1;
  target.digest = sha256(target.bytes);
  assert.throws(
    () => createExactHandoffStorePolicy(tamperedBytes),
    hasCode("store_plan_invalid"),
  );

  const duplicate = cloneStorePlan(plan);
  duplicate.blobs.push({
    ...duplicate.blobs[0]!,
    bytes: new Uint8Array(duplicate.blobs[0]!.bytes),
  });
  assert.throws(
    () => createExactHandoffStorePolicy(duplicate),
    hasCode("store_plan_invalid"),
  );

  const tooManyBlobs = {
    ...plan,
    blobs: Array(4098).fill(plan.blobs[0]),
  } as HandoffStoreWritePlan;
  assert.throws(
    () => createExactHandoffStorePolicy(tooManyBlobs),
    hasCode("store_plan_invalid"),
  );
  const tooManyEvents = {
    ...plan,
    events: Array(130).fill(plan.events[0]),
  } as HandoffStoreWritePlan;
  assert.throws(
    () => createExactHandoffStorePolicy(tooManyEvents),
    hasCode("store_plan_invalid"),
  );

  let blobWrites = 0;
  let eventWrites = 0;
  const writer = {
    async putBlob() {
      blobWrites += 1;
      throw new Error("must not write");
    },
    async appendEvent() {
      eventWrites += 1;
      throw new Error("must not write");
    },
  };
  await assert.rejects(
    persistApprovedHandoff(writer, tamperedBytes),
    hasCode("store_plan_invalid"),
  );
  assert.equal(blobWrites, 0);
  assert.equal(eventWrites, 0);
});

test("persistence rejects a writer receipt that does not prove the expected content address", async () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const approved = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  let eventWrites = 0;
  const writer = {
    async putBlob(request: { bytes: Uint8Array }) {
      return {
        digest: sha256(request.bytes),
        byteLength: request.bytes.byteLength,
        relativePath: "blobs/sha256/not-the-content-address",
        disposition: "stored" as const,
      };
    },
    async appendEvent() {
      eventWrites += 1;
      throw new Error("must not append after a false blob receipt");
    },
  };
  await assert.rejects(
    persistApprovedHandoff(writer, approved.storeWritePlan),
    hasCode("store_plan_invalid"),
  );
  assert.equal(eventWrites, 0);
});

test("repeated approval produces byte-identical archives and exact store plans", () => {
  const identity = new CountingIdentity();
  const input = makeInput(identity);
  const inspection = inspectHandoff(input);
  const first = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  const second = createApprovedHandoff({
    ...input,
    approvalDigest: inspection.approvalDigest,
  });
  assert.deepEqual(first.archive, second.archive);
  assert.deepEqual(first.storeWritePlan, second.storeWritePlan);
  assert.equal(identity.archiveCalls, 2);
});

function makeInput(identity: DeviceSigningIdentity): InspectHandoffInput {
  return {
    entireCheckpointDetailJson: JSON.stringify({
      checkpoint_id: EXTERNAL_CHECKPOINT_ID,
      strategy: "manual-commit",
      branch: "feature/handoff",
      message: "MESSAGE_CANARY",
      files_touched: ["FILE_CANARY"],
      session_count: 1,
      sessions: [
        {
          index: 0,
          session_id: "external-session-1",
          agent: "Codex",
          model: "provider-model",
          kind: "coding",
          created_at: "2026-08-07T11:55:00Z",
          files_touched: ["FILE_CANARY"],
          summary: {
            intent: "SUMMARY_CANARY",
            outcome: "MESSAGE_CANARY",
            friction: [],
            open_items: [],
            learnings: { repo: [], code: [], workflow: [] },
          },
          raw_transcript: "TRANSCRIPT_CANARY",
          prompts: ["PROMPT_CANARY"],
          responses: ["RESPONSE_CANARY"],
        },
      ],
      unknown_private: "UNKNOWN_CANARY",
    }),
    plan: makePlan(),
    capturedAt: CAPTURED_AT,
    git: makeGit(),
    signingIdentity: identity,
  };
}

function makePlan(): OperatorHandoffPlan {
  return {
    source: {
      provider: "entire",
      providerVersion: "0.9.0",
      externalCheckpointId: EXTERNAL_CHECKPOINT_ID,
    },
    actor: { id: "human-alice", displayName: "Alice" },
    spaceId: "space-open-work",
    work: {
      workItemId: "OWC-12",
      title: "Portable handoff proof",
      objective: "Resume exact work without provider history.",
      constraints: [
        "Do not import provider transcripts.",
        "Treat Git state as exact local evidence.",
      ],
    },
    decisions: [
      "Use Entire only as a replaceable capture adapter.",
      "Keep provider-authored summaries outside the archive.",
    ],
    openQuestions: ["Which second provider should prove portability next?"],
    nextAction: "Run the independent resume path in a fresh worktree.",
    sensitivity: "private",
    retention: { class: "checkpoint", expiresAt: null },
  };
}

function makeGit(
  capturedAt = CAPTURED_AT,
  artifactText = "operator-approved untracked note\n",
): CapturedGitState {
  const artifactBytes = Buffer.from(artifactText, "utf8");
  const artifactDigest = sha256(artifactBytes);
  const artifactPath = "artifacts/git/untracked/notes/handoff.txt";
  const state: GitStateV0 = {
    schema_version: "0.1",
    repository_id: "urn:owc:repository:test",
    object_format: "sha1",
    captured_at: capturedAt,
    base_commit: "1".repeat(40),
    head_commit: "2".repeat(40),
    head_tree: "3".repeat(40),
    head_ref: "refs/heads/feature/handoff",
    worktree: {
      clean: false,
      untracked: [
        {
          path: "notes/handoff.txt",
          included: true,
          digest: artifactDigest,
          byte_length: artifactBytes.byteLength,
          artifact: {
            path: artifactPath,
            digest: artifactDigest,
            byte_length: artifactBytes.byteLength,
          },
        },
      ],
    },
  };
  const stateBytes = canonicalJsonBytes(state);
  return {
    state,
    stateBytes,
    stateDigest: sha256(stateBytes),
    patchArtifact: null,
    untrackedArtifacts: [
      {
        path: artifactPath,
        mediaType: "application/octet-stream",
        bytes: artifactBytes,
        digest: artifactDigest,
        byteLength: artifactBytes.byteLength,
      },
    ],
  };
}

function driftGit(input: CapturedGitState): CapturedGitState {
  const state: GitStateV0 = {
    ...input.state,
    head_ref: "refs/heads/feature/drifted",
  };
  const stateBytes = canonicalJsonBytes(state);
  return {
    ...input,
    state,
    stateBytes,
    stateDigest: sha256(stateBytes),
  };
}

class CountingIdentity implements DeviceSigningIdentity {
  readonly #key: GeneratedSigningKey;
  readonly publicIdentity: PublicDeviceIdentity;
  signCalls = 0;
  archiveCalls = 0;
  lastArchive: LogicalArchive | null = null;

  constructor() {
    this.#key = generateArchiveSigningKey();
    this.publicIdentity = {
      format: "open-work-commons-device-identity",
      schema_version: "0.1",
      algorithm: "ed25519",
      key_id: this.#key.keyId,
      fingerprint: this.#key.fingerprint,
      public_key: this.#key.publicKeyBase64Url,
      public_key_spki: this.#key.publicKey
        .export({ format: "der", type: "spki" })
        .toString("base64url"),
    };
  }

  sign(): string {
    this.signCalls += 1;
    throw new Error("The handoff library must not call the raw signer.");
  }

  createSignedArchive(input: UnsignedArchiveInput) {
    this.archiveCalls += 1;
    this.lastArchive = signArchive({
      ...input,
      signingKey: {
        keyId: this.publicIdentity.key_id,
        privateKey: this.#key.privateKey,
      },
    });
    return this.lastArchive;
  }
}

class SubstitutingIdentity implements DeviceSigningIdentity {
  readonly publicIdentity: PublicDeviceIdentity;
  readonly #actual = generateArchiveSigningKey();
  archiveCalls = 0;

  constructor(publicIdentity: PublicDeviceIdentity) {
    this.publicIdentity = publicIdentity;
  }

  sign(): string {
    throw new Error("must not call raw signer");
  }

  createSignedArchive(input: UnsignedArchiveInput) {
    this.archiveCalls += 1;
    return signArchive({
      ...input,
      signingKey: {
        keyId: this.#actual.keyId,
        privateKey: this.#actual.privateKey,
      },
    });
  }
}

function wrapIdentity(
  delegate: DeviceSigningIdentity,
  publicIdentity: PublicDeviceIdentity,
): DeviceSigningIdentity {
  return {
    publicIdentity,
    sign: (payload) => delegate.sign(payload),
    createSignedArchive: (input) => delegate.createSignedArchive(input),
  };
}

function mutateEntireDetail(
  input: string,
  mutate: (detail: Record<string, unknown>) => void,
): string {
  const detail = JSON.parse(input) as Record<string, unknown>;
  mutate(detail);
  return JSON.stringify(detail);
}

function approvalProjectionDigest(inspection: HandoffInspection): string {
  const record = cloneInspection(inspection) as unknown as Record<
    string,
    unknown
  >;
  delete record.approvalDigest;
  return sha256(canonicalJsonBytes(record));
}

function cloneInspection(input: HandoffInspection): HandoffInspection {
  return JSON.parse(JSON.stringify(input)) as HandoffInspection;
}

function collectKeys(value: unknown, output = new Set<string>()): Set<string> {
  if (!value || typeof value !== "object") return output;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, output);
    return output;
  }
  for (const [key, item] of Object.entries(value)) {
    output.add(key);
    collectKeys(item, output);
  }
  return output;
}

function cloneStorePlan(input: HandoffStoreWritePlan): {
  format: HandoffStoreWritePlan["format"];
  schemaVersion: HandoffStoreWritePlan["schemaVersion"];
  approvalDigest: HandoffStoreWritePlan["approvalDigest"];
  archiveId: string;
  blobs: Array<{
    archivePath: string;
    mediaType: string;
    digest: HandoffStoreWritePlan["blobs"][number]["digest"];
    byteLength: number;
    bytes: Uint8Array;
  }>;
  events: HandoffStoreWritePlan["events"][number][];
} {
  return {
    ...input,
    blobs: input.blobs.map((item) => ({
      ...item,
      bytes: new Uint8Array(item.bytes),
    })),
    events: input.events.map((item) => ({
      ...item,
      event: JSON.parse(JSON.stringify(item.event)),
    })),
  };
}

function hasCode(code: HandoffError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof HandoffError && error.code === code;
}
