import { createPublicKey } from "node:crypto";

import {
  canonicalJsonBytes,
  isSafeArchivePath,
  parseJsonSafely,
  sha256,
  type Digest,
} from "../../archive/src/index.js";
import { validateGitState } from "../../archive/src/validation.js";
import type {
  CapturedGitState,
  GitStateArtifact,
} from "../../git-state/src/index.js";
import type { DeviceSigningIdentity } from "../../identity/src/index.js";

import {
  HandoffError,
  type HandoffArtifactReview,
  type HandoffRetentionClass,
  type HandoffSensitivity,
  type NormalizedOperatorHandoffPlan,
  type OperatorHandoffPlan,
} from "./types.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,511}$/;
const SAFE_EXTERNAL_ID = /^[A-Za-z0-9._:-]+$/;
const ENTIRE_09_VERSION = /^0\.9(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(Z|([+-])(\d{2}):(\d{2}))$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

const MAX_LIST_ITEMS = 128;
const JSON_LIMITS = {
  maxDepth: 64,
  maxStringBytes: 1024 * 1024,
} as const;

export interface ValidatedSignerIdentity {
  readonly keyId: string;
  readonly fingerprint: Digest;
  readonly publicKey: string;
}

export function normalizePlan(
  input: OperatorHandoffPlan,
): NormalizedOperatorHandoffPlan {
  const root = requireRecord(input, "invalid_plan");
  exactKeys(
    root,
    [
      "source",
      "actor",
      "spaceId",
      "work",
      "nextAction",
      "sensitivity",
      "retention",
    ],
    ["decisions", "openQuestions"],
  );

  const source = requireRecord(root.source, "invalid_plan");
  exactKeys(source, ["provider", "providerVersion", "externalCheckpointId"]);
  if (source.provider !== "entire") {
    throw new HandoffError(
      "provider_mismatch",
      "The v0 handoff source provider must be Entire.",
    );
  }
  const providerVersion = safeText(source.providerVersion, 128);
  if (!ENTIRE_09_VERSION.test(providerVersion)) {
    throw new HandoffError(
      "provider_mismatch",
      "The v0 handoff accepts only an explicitly bound Entire 0.9 provider version.",
    );
  }
  const externalCheckpointId = safeIdentifier(
    source.externalCheckpointId,
    SAFE_EXTERNAL_ID,
    512,
  );

  const actor = requireRecord(root.actor, "invalid_plan");
  exactKeys(actor, ["id"], ["displayName"]);
  const actorId = safeIdentifier(actor.id, SAFE_IDENTIFIER, 512);
  const displayName =
    actor.displayName === undefined
      ? undefined
      : safeText(actor.displayName, 256);

  const work = requireRecord(root.work, "invalid_plan");
  exactKeys(work, ["workItemId", "title", "objective", "constraints"]);
  const constraints = stringList(work.constraints, 4096);
  const decisions = stringList(root.decisions ?? [], 8192);
  const openQuestions = stringList(root.openQuestions ?? [], 4096);
  requireUnique(constraints);
  requireUnique(decisions);
  requireUnique(openQuestions);

  const sensitivity = root.sensitivity;
  if (!isSensitivity(sensitivity)) {
    throw invalidPlan();
  }
  const retention = requireRecord(root.retention, "invalid_plan");
  exactKeys(retention, ["class", "expiresAt"]);
  if (!isRetentionClass(retention.class)) {
    throw invalidPlan();
  }
  const expiresAt = retention.expiresAt;
  if (expiresAt !== null) assertRfc3339(expiresAt, "invalid_plan");

  return {
    source: {
      provider: "entire",
      providerVersion,
      externalCheckpointId,
    },
    actor: {
      id: actorId,
      ...(displayName === undefined ? {} : { displayName }),
    },
    spaceId: safeIdentifier(root.spaceId, SAFE_IDENTIFIER, 512),
    work: {
      workItemId: safeIdentifier(work.workItemId, SAFE_IDENTIFIER, 512),
      title: safeText(work.title, 512),
      objective: safeText(work.objective, 8192),
      constraints,
    },
    decisions,
    openQuestions,
    nextAction: safeText(root.nextAction, 8192),
    sensitivity,
    retention: { class: retention.class, expiresAt },
  };
}

export function validateCapturedGitState(
  git: CapturedGitState,
  capturedAt: string,
): readonly HandoffArtifactReview[] {
  if (!git || typeof git !== "object") throw invalidGit();
  if (!(git.stateBytes instanceof Uint8Array) || !isDigest(git.stateDigest)) {
    throw invalidGit();
  }
  if (sha256(git.stateBytes) !== git.stateDigest) throw invalidGit();

  let parsed: unknown;
  try {
    parsed = parseJsonSafely(git.stateBytes, JSON_LIMITS);
  } catch {
    throw invalidGit();
  }
  const stateValidation = validateGitState(parsed, "$.git_state");
  if (!stateValidation.value || stateValidation.problems.length > 0) {
    throw invalidGit();
  }
  let canonicalState: Uint8Array;
  let canonicalParsed: Uint8Array;
  try {
    canonicalState = canonicalJsonBytes(git.state);
    canonicalParsed = canonicalJsonBytes(parsed);
  } catch {
    throw invalidGit();
  }
  if (
    !sameBytes(canonicalState, git.stateBytes) ||
    !sameBytes(canonicalParsed, git.stateBytes)
  ) {
    throw invalidGit();
  }
  if (git.state.captured_at !== capturedAt) throw invalidGit();

  const expected = new Map<
    string,
    {
      readonly digest: Digest;
      readonly byteLength: number;
      readonly mediaType: string;
      readonly role: "git-patch" | "git-untracked-file";
    }
  >();
  if (git.state.worktree.patch) {
    addExpected(expected, git.state.worktree.patch.path, {
      digest: git.state.worktree.patch.digest,
      byteLength: git.state.worktree.patch.byte_length,
      mediaType: "application/vnd.openworkcommons.git-patch-v1",
      role: "git-patch",
    });
  }
  for (const item of git.state.worktree.untracked) {
    if (!item.included) continue;
    addExpected(expected, item.artifact.path, {
      digest: item.artifact.digest,
      byteLength: item.artifact.byte_length,
      mediaType: "application/octet-stream",
      role: "git-untracked-file",
    });
  }

  const supplied: readonly GitStateArtifact[] = [
    ...(git.patchArtifact === null ? [] : [git.patchArtifact]),
    ...git.untrackedArtifacts,
  ];
  if (supplied.length !== expected.size) throw invalidGit();
  const seen = new Set<string>();
  const reviews: HandoffArtifactReview[] = [];
  for (const artifact of supplied) {
    if (
      !artifact ||
      !(artifact.bytes instanceof Uint8Array) ||
      !isSafeArchivePath(artifact.path) ||
      seen.has(artifact.path)
    ) {
      throw invalidGit();
    }
    seen.add(artifact.path);
    const reference = expected.get(artifact.path);
    if (
      !reference ||
      artifact.digest !== reference.digest ||
      artifact.byteLength !== reference.byteLength ||
      artifact.bytes.byteLength !== reference.byteLength ||
      sha256(artifact.bytes) !== reference.digest ||
      artifact.mediaType !== reference.mediaType
    ) {
      throw invalidGit();
    }
    reviews.push({
      path: artifact.path,
      mediaType: artifact.mediaType,
      digest: artifact.digest,
      byteLength: artifact.byteLength,
      role: reference.role,
    });
  }
  for (const path of expected.keys()) {
    if (!seen.has(path)) throw invalidGit();
  }
  return reviews.sort((left, right) => compareStrings(left.path, right.path));
}

function addExpected<T>(
  expected: Map<string, T>,
  path: string,
  value: T,
): void {
  if (expected.has(path)) throw invalidGit();
  expected.set(path, value);
}

export function validateSigningIdentity(
  identity: DeviceSigningIdentity,
): ValidatedSignerIdentity {
  if (
    !identity ||
    typeof identity !== "object" ||
    typeof identity.sign !== "function" ||
    typeof identity.createSignedArchive !== "function"
  ) {
    throw invalidIdentity();
  }
  const value = identity.publicIdentity;
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) ||
    !hasExactKeys(value as unknown as Record<string, unknown>, [
      "format",
      "schema_version",
      "algorithm",
      "key_id",
      "fingerprint",
      "public_key",
      "public_key_spki",
    ]) ||
    value.format !== "open-work-commons-device-identity" ||
    value.schema_version !== "0.1" ||
    value.algorithm !== "ed25519" ||
    typeof value.key_id !== "string" ||
    value.key_id.length < 1 ||
    value.key_id.length > 512 ||
    Buffer.byteLength(value.key_id, "utf8") > 512 ||
    value.key_id.trim() !== value.key_id ||
    value.key_id.normalize("NFC") !== value.key_id ||
    UNSAFE_TEXT.test(value.key_id) ||
    !isDigest(value.fingerprint) ||
    typeof value.public_key !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.public_key) ||
    typeof value.public_key_spki !== "string" ||
    !/^[A-Za-z0-9_-]{59}$/.test(value.public_key_spki)
  ) {
    throw invalidIdentity();
  }
  const raw = Buffer.from(value.public_key, "base64url");
  const spki = Buffer.from(value.public_key_spki, "base64url");
  if (
    raw.byteLength !== 32 ||
    raw.toString("base64url") !== value.public_key ||
    spki.byteLength !== 44 ||
    spki.toString("base64url") !== value.public_key_spki ||
    sha256(raw) !== value.fingerprint ||
    !spkiMatchesRawPublicKey(spki, value.public_key)
  ) {
    throw invalidIdentity();
  }
  return {
    keyId: value.key_id,
    fingerprint: value.fingerprint,
    publicKey: value.public_key,
  };
}

export function assertRfc3339(
  input: unknown,
  code: "invalid_input" | "invalid_plan" = "invalid_input",
): asserts input is string {
  if (typeof input !== "string") {
    throw new HandoffError(code, "A strict RFC 3339 timestamp is required.");
  }
  if (input.length > 128) {
    throw new HandoffError(code, "A strict RFC 3339 timestamp is required.");
  }
  const match = RFC3339.exec(input);
  if (!match) {
    throw new HandoffError(code, "A strict RFC 3339 timestamp is required.");
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetSign = match[8] === "-" ? -1 : 1;
  const offsetHour = Number(match[9] ?? 0);
  const offsetMinute = Number(match[10] ?? 0);
  const monthDays = [
    0,
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const validDate =
    month >= 1 && month <= 12 && day >= 1 && day <= (monthDays[month] ?? 0);
  const ordinaryTime = hour <= 23 && minute <= 59 && second < 60;
  const utcMinute = minute - offsetMinute * offsetSign;
  const utcHour = hour - offsetHour * offsetSign - (utcMinute < 0 ? 1 : 0);
  const leapSecond =
    hour <= 23 &&
    minute <= 59 &&
    second >= 60 &&
    (utcHour === 23 || utcHour === -1) &&
    (utcMinute === 59 || utcMinute === -1) &&
    second < 61;
  const validTime =
    offsetHour <= 23 && offsetMinute <= 59 && (ordinaryTime || leapSecond);
  if (!validDate || !validTime) {
    throw new HandoffError(code, "A strict RFC 3339 timestamp is required.");
  }
}

export function isDigest(value: unknown): value is Digest {
  return typeof value === "string" && DIGEST.test(value);
}

function requireRecord(
  value: unknown,
  code: "invalid_plan" | "git_state_invalid",
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw new HandoffError(code, "The handoff input has an invalid shape.");
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw invalidPlan();
  }
}

function safeText(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    Buffer.byteLength(value, "utf8") > maximum ||
    value.trim() !== value ||
    UNSAFE_TEXT.test(value) ||
    value.normalize("NFC") !== value ||
    Buffer.from(value, "utf8").toString("utf8") !== value
  ) {
    throw invalidPlan();
  }
  return value;
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key))
  );
}

function spkiMatchesRawPublicKey(
  spki: Uint8Array,
  expectedRawPublicKey: string,
): boolean {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(spki),
      format: "der",
      type: "spki",
    });
    if (
      publicKey.type !== "public" ||
      publicKey.asymmetricKeyType !== "ed25519"
    ) {
      return false;
    }
    const canonical = publicKey.export({ format: "der", type: "spki" });
    const jwk = publicKey.export({ format: "jwk" });
    return (
      Buffer.isBuffer(canonical) &&
      Buffer.from(canonical).equals(Buffer.from(spki)) &&
      jwk.kty === "OKP" &&
      jwk.crv === "Ed25519" &&
      jwk.x === expectedRawPublicKey
    );
  } catch {
    return false;
  }
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function safeIdentifier(
  value: unknown,
  pattern: RegExp,
  maximum: number,
): string {
  const text = safeText(value, maximum);
  if (!pattern.test(text)) throw invalidPlan();
  return text;
}

function stringList(value: unknown, maximumLength: number): readonly string[] {
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    throw invalidPlan();
  }
  return value.map((item) => safeText(item, maximumLength));
}

function requireUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) throw invalidPlan();
}

function isSensitivity(value: unknown): value is HandoffSensitivity {
  return (
    value === "public" ||
    value === "internal" ||
    value === "private" ||
    value === "restricted"
  );
}

function isRetentionClass(value: unknown): value is HandoffRetentionClass {
  return (
    value === "ephemeral" ||
    value === "checkpoint" ||
    value === "archive" ||
    value === "legal-hold"
  );
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalidPlan(): HandoffError {
  return new HandoffError(
    "invalid_plan",
    "The operator handoff plan is not strict, bounded, and safe.",
  );
}

function invalidGit(): HandoffError {
  return new HandoffError(
    "git_state_invalid",
    "The captured Git state or its exact artifacts are invalid or inconsistent.",
  );
}

function invalidIdentity(): HandoffError {
  return new HandoffError(
    "signing_identity_invalid",
    "The device signing capability has an invalid public identity.",
  );
}
