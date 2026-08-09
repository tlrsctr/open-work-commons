import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const candidate = process.env.OWC_BENCHMARK_CANDIDATE;
if (!candidate || !candidate.startsWith("/")) {
  throw new Error("OWC_BENCHMARK_CANDIDATE must be an absolute path.");
}
const moduleUrl = pathToFileURL(
  resolve(candidate, "src/promotion-gate.js"),
).href;
const { evaluatePromotionGate } = await import(moduleUrl);

const SUBJECT = `sha256:${"a".repeat(64)}`;
const OTHER = `sha256:${"b".repeat(64)}`;
const BASE_POLICY = Object.freeze({
  subject_digest: SUBJECT,
  required_checks: Object.freeze(["unit"]),
  as_of: "2026-08-07T12:00:00Z",
  max_age_seconds: 3600,
});

test("rejects invalid policy and evidence timestamps", () => {
  assert.throws(
    () =>
      evaluatePromotionGate({
        policy: { ...BASE_POLICY, as_of: "nope" },
        evidence: [],
      }),
    TypeError,
  );
  assert.throws(
    () =>
      evaluatePromotionGate({
        policy: BASE_POLICY,
        evidence: [item("unit", "passed", "2026-02-29T11:00:00Z")],
      }),
    TypeError,
  );
});

test("rejects duplicate required check identifiers", () => {
  assert.throws(
    () =>
      evaluatePromotionGate({
        policy: { ...BASE_POLICY, required_checks: ["unit", "unit"] },
        evidence: [],
      }),
    TypeError,
  );
});

test("distinguishes subject mismatch from missing", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [
        {
          ...item("unit", "passed", "2026-08-07T11:30:00Z"),
          subject_digest: OTHER,
        },
      ],
    }),
    {
      allowed: false,
      blockers: [{ check_id: "unit", reason: "subject_mismatch" }],
    },
  );
});

test("uses exact-subject evidence even when another subject is newer", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [
        item("unit", "passed", "2026-08-07T11:30:00Z"),
        {
          ...item("unit", "failed", "2026-08-07T11:59:00Z"),
          subject_digest: OTHER,
        },
      ],
    }),
    { allowed: true, blockers: [] },
  );
});

test("future-only evidence is not current", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [item("unit", "passed", "2026-08-07T12:00:01Z")],
    }),
    {
      allowed: false,
      blockers: [{ check_id: "unit", reason: "future" }],
    },
  );
});

test("selects the latest non-future observation", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [
        item("unit", "failed", "2026-08-07T11:00:00Z"),
        item("unit", "passed", "2026-08-07T11:30:00Z"),
        item("unit", "failed", "2026-08-07T12:30:00Z"),
      ],
    }),
    { allowed: true, blockers: [] },
  );
});

test("rejects conflicting observations at the latest timestamp", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [
        item("unit", "passed", "2026-08-07T11:30:00Z"),
        item("unit", "failed", "2026-08-07T11:30:00Z"),
      ],
    }),
    {
      allowed: false,
      blockers: [{ check_id: "unit", reason: "ambiguous" }],
    },
  );
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [
        item("unit", "passed", "2026-08-07T11:30:00Z"),
        item("unit", "passed", "2026-08-07T11:30:00Z"),
      ],
    }),
    { allowed: true, blockers: [] },
  );
});

test("applies the inclusive freshness boundary before result mapping", () => {
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [item("unit", "passed", "2026-08-07T11:00:00Z")],
    }),
    { allowed: true, blockers: [] },
  );
  assert.deepEqual(
    evaluatePromotionGate({
      policy: BASE_POLICY,
      evidence: [item("unit", "failed", "2026-08-07T10:59:59Z")],
    }),
    {
      allowed: false,
      blockers: [{ check_id: "unit", reason: "stale" }],
    },
  );
});

test("maps current failed and unknown results exactly", () => {
  for (const reason of ["failed", "unknown"]) {
    assert.deepEqual(
      evaluatePromotionGate({
        policy: BASE_POLICY,
        evidence: [item("unit", reason, "2026-08-07T11:30:00Z")],
      }),
      {
        allowed: false,
        blockers: [{ check_id: "unit", reason }],
      },
    );
  }
});

test("returns one sorted blocker per required check without mutating inputs", () => {
  const policy = {
    ...BASE_POLICY,
    required_checks: ["zeta", "alpha", "middle"],
  };
  const evidence = [item("middle", "unknown", "2026-08-07T11:30:00Z")];
  const before = JSON.stringify({ policy, evidence });
  assert.deepEqual(evaluatePromotionGate({ policy, evidence }), {
    allowed: false,
    blockers: [
      { check_id: "alpha", reason: "missing" },
      { check_id: "middle", reason: "unknown" },
      { check_id: "zeta", reason: "missing" },
    ],
  });
  assert.equal(JSON.stringify({ policy, evidence }), before);
});

function item(check_id, result, observed_at) {
  return { check_id, subject_digest: SUBJECT, result, observed_at };
}
