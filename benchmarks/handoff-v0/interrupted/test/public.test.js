import assert from "node:assert/strict";
import test from "node:test";

import { evaluatePromotionGate } from "../src/promotion-gate.js";

const policy = {
  subject_digest: `sha256:${"a".repeat(64)}`,
  required_checks: ["unit", "lint"],
  as_of: "2026-08-07T12:00:00Z",
  max_age_seconds: 3600,
};

test("allows current passing evidence for every required check", () => {
  const result = evaluatePromotionGate({
    policy,
    evidence: [
      evidence("unit", "passed", "2026-08-07T11:30:00Z"),
      evidence("lint", "passed", "2026-08-07T11:45:00Z"),
    ],
  });
  assert.deepEqual(result, { allowed: true, blockers: [] });
});

test("denies missing and failed evidence in stable order", () => {
  const result = evaluatePromotionGate({
    policy,
    evidence: [evidence("unit", "failed", "2026-08-07T11:30:00Z")],
  });
  assert.deepEqual(result, {
    allowed: false,
    blockers: [
      { check_id: "lint", reason: "missing" },
      { check_id: "unit", reason: "failed" },
    ],
  });
});

function evidence(check_id, result, observed_at) {
  return {
    check_id,
    subject_digest: policy.subject_digest,
    result,
    observed_at,
  };
}
