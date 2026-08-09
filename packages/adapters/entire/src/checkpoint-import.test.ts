import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  importEntireCheckpointDetail,
  importEntireCheckpointList,
} from "./checkpoint-import.js";

const LIST_FIXTURE = readFixture("checkpoint-list.sanitized.json");
const DETAIL_FIXTURE = readFixture("checkpoint-detail.sanitized.json");
const DUPLICATE_KEY_FIXTURE = readFixture(
  "checkpoint-detail.duplicate-key.json",
);

test("projects checkpoint listings into explicit incomplete OWC candidates", () => {
  const result = importEntireCheckpointList(LIST_FIXTURE, {
    providerVersion: "0.9.0",
  });

  assert.equal(result.status, "ok");
  if (result.status !== "ok") return;

  assert.equal(result.checkpoints.length, 2);
  assert.equal(result.events.length, 2);
  const first = result.checkpoints[0];
  assert.ok(first);
  assert.equal(first.source.provider, "entire");
  assert.equal(first.source.providerVersion, "0.9.0");
  assert.equal(first.providerTimestamp, "2026-08-07T10:15:30.000Z");
  assert.deepEqual(first.externalSessionIds, ["session-alpha"]);
  assert.equal(
    first.providerMessage?.value,
    "Add a provider-neutral archive boundary",
  );
  assert.ok(first.gaps.includes("checkpoint_detail_not_imported"));
  assert.ok(first.gaps.includes("git_state_unavailable"));
  assert.equal(result.events[0]?.proposedEventType, null);
  assert.ok(result.events[0]?.gaps.includes("owc_event_type_unavailable"));

  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /RAW_TRANSCRIPT_CANARY/);
  assert.doesNotMatch(serialized, /UNKNOWN_PRIVATE_CANARY/);
  assert.doesNotMatch(serialized, /raw_transcript|unknown_private/);
});

test("imports metadata-only checkpoint detail without promoting claims to evidence", () => {
  const result = importEntireCheckpointDetail(DETAIL_FIXTURE, {
    providerVersion: "0.9.0",
  });

  assert.equal(result.status, "ok");
  if (result.status !== "ok") return;

  const checkpoint = result.checkpoints[0];
  const session = checkpoint?.sessions[0];
  assert.ok(checkpoint);
  assert.ok(session);
  assert.equal(checkpoint.completeness, "metadata");
  assert.equal(checkpoint.providerBranch, "feature/archive-boundary");
  assert.deepEqual(checkpoint.providerReportedFiles, [
    "src/archive.ts",
    "test/archive.test.ts",
  ]);
  assert.deepEqual(session.tokenUsage, {
    input: 120,
    output: 80,
    cacheRead: 30,
    cacheCreation: 10,
  });
  assert.equal(
    session.providerSummaryClaims?.outcome?.value,
    "A metadata-only projection is ready for review.",
  );
  assert.equal(
    session.providerSummaryClaims?.learnings.code[0]?.finding.value,
    "Keep provider assertions separate from evidence.",
  );
  assert.equal(
    result.events[0]?.providerSummaryClaims,
    session.providerSummaryClaims,
  );
  assert.ok(checkpoint.gaps.includes("event_history_unavailable"));
  assert.ok(checkpoint.gaps.includes("next_action_requires_operator"));
  assert.deepEqual(
    checkpoint.exclusions.map((exclusion) => exclusion.category),
    ["raw-transcript", "unknown-provider-fields"],
  );
  assert.equal(
    checkpoint.handling.authorizationRequiredBeforeDurableWrite,
    true,
  );

  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /DETAIL_TRANSCRIPT_CANARY/);
  assert.doesNotMatch(serialized, /DETAIL_PROMPT_CANARY/);
  assert.doesNotMatch(serialized, /DETAIL_RESPONSE_CANARY/);
  assert.doesNotMatch(serialized, /DETAIL_PRIVATE_CANARY/);
  assert.doesNotMatch(serialized, /raw_transcript|prompts|responses/);
  assert.doesNotMatch(serialized, /"evidence"\s*:/);
});

test("rejects duplicate JSON keys before projection", () => {
  const result = importEntireCheckpointDetail(DUPLICATE_KEY_FIXTURE);

  assert.deepEqual(result, {
    status: "invalid",
    diagnostic: "entire_checkpoint_json_duplicate_key",
    checkpoints: [],
    events: [],
  });
});

test("represents partial session metadata without returning provider error text", () => {
  const result = importEntireCheckpointDetail(
    JSON.stringify({
      checkpoint_id: "01KVBJCWYA4YW6J5M9GP655HZN",
      session_count: 1,
      partial: true,
      sessions: [
        {
          index: 0,
          error: "read failed at /private/SECRET_ERROR_CANARY/transcript.jsonl",
        },
      ],
    }),
  );

  assert.equal(result.status, "ok");
  if (result.status !== "ok") return;
  const checkpoint = result.checkpoints[0];
  assert.equal(checkpoint?.sessions[0]?.metadataAvailable, false);
  assert.ok(checkpoint?.gaps.includes("provider_metadata_partial"));
  assert.ok(
    checkpoint?.sessions[0]?.gaps.includes(
      "provider_session_metadata_unavailable",
    ),
  );
  assert.doesNotMatch(
    JSON.stringify(result),
    /SECRET_ERROR_CANARY|transcript\.jsonl/,
  );
});

test("fails closed on unsafe provider-reported paths", () => {
  const result = importEntireCheckpointDetail(
    JSON.stringify({
      checkpoint_id: "01KVBJCWYA4YW6J5M9GP655HZN",
      files_touched: ["../../PRIVATE_PATH_CANARY"],
      session_count: 0,
      sessions: [],
    }),
  );

  assert.equal(result.status, "invalid");
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_PATH_CANARY/);
});

function readFixture(name: string): string {
  return readFileSync(
    new URL(`../test/fixtures/${name}`, import.meta.url),
    "utf8",
  );
}
