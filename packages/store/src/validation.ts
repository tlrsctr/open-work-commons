import { canonicalJsonBytes } from "../../archive/src/canonical-json.js";
import { isSafeArchivePath } from "../../archive/src/path.js";
import { parseJsonSafely } from "../../archive/src/safe-json.js";

import { sha256Digest } from "./crypto.js";
import { LocalStoreError } from "./errors.js";
import type { Digest, NormalizedEventEnvelope, StoreLimits } from "./types.js";

const EVENT_ID = /^urn:owc:event:[A-Za-z0-9._:-]+$/;
const CORE_EVENT_TYPES = new Set<string>([
  "session.started",
  "context.declared",
  "tool.observed",
  "artifact.changed",
  "evidence.observed",
  "human.intervened",
  "checkpoint.requested",
  "session.ended",
]);
const NAMESPACED_EVENT_TYPE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/;
const PROVIDER_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SUBJECT_KIND = /^[a-z][a-z0-9._-]{0,127}$/;
const EXTENSION_KEY = /^[a-z0-9][a-z0-9.-]*\/[A-Za-z0-9._-]+$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const RFC3339_DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(Z|([+-])(\d{2}):(\d{2}))$/;

export interface ValidatedEvent {
  readonly event: NormalizedEventEnvelope;
  readonly bytes: Uint8Array;
  readonly digest: Digest;
}

export function boundedPolicyEventClone(
  value: unknown,
  limits: StoreLimits,
): unknown {
  const bytes = boundedCanonicalBytes(value, limits);
  return deepFreeze(parseCanonicalBytes(bytes, limits));
}

export function validateAuthorizedEvent(
  value: unknown,
  limits: StoreLimits,
): ValidatedEvent {
  const bytes = boundedCanonicalBytes(value, limits);
  const parsed = parseCanonicalBytes(bytes, limits);
  validateEventShape(parsed, limits);
  return {
    event: parsed as unknown as NormalizedEventEnvelope,
    bytes,
    digest: sha256Digest(bytes),
  };
}

export function validateStoredEventBytes(
  storedBytes: Uint8Array,
  limits: StoreLimits,
): ValidatedEvent {
  if (storedBytes.byteLength > limits.maxEventBytes) {
    throw new LocalStoreError("resource_limit");
  }
  const parsed = parseCanonicalBytes(storedBytes, limits);
  const validated = validateAuthorizedEvent(parsed, limits);
  if (!Buffer.from(validated.bytes).equals(Buffer.from(storedBytes))) {
    throw new LocalStoreError("integrity_failure");
  }
  return validated;
}

export function isDigest(value: unknown): value is Digest {
  return typeof value === "string" && DIGEST.test(value);
}

export function validateEventId(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !EVENT_ID.test(value)
  ) {
    throw new LocalStoreError("invalid_input");
  }
}

function boundedCanonicalBytes(
  value: unknown,
  limits: StoreLimits,
): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = canonicalJsonBytes(value, {
      maxDepth: limits.maxJsonDepth,
      maxStringBytes: limits.maxJsonStringBytes,
    });
  } catch (error) {
    throw new LocalStoreError(
      error instanceof RangeError ? "resource_limit" : "invalid_input",
    );
  }
  if (bytes.byteLength > limits.maxEventBytes) {
    throw new LocalStoreError("resource_limit");
  }
  return bytes;
}

function parseCanonicalBytes(bytes: Uint8Array, limits: StoreLimits): unknown {
  try {
    return parseJsonSafely(bytes, {
      maxDepth: limits.maxJsonDepth,
      maxStringBytes: limits.maxJsonStringBytes,
    });
  } catch {
    throw new LocalStoreError("invalid_input");
  }
}

function validateEventShape(value: unknown, limits: StoreLimits): void {
  const event = exactObject(
    value,
    [
      "schema_version",
      "event_id",
      "event_type",
      "recorded_at",
      "actor",
      "space_id",
      "session_id",
      "sequence",
      "previous_event_id",
      "provider",
      "subject",
      "payload",
      "sensitivity",
      "retention",
    ],
    ["effective_at", "extensions"],
  );
  equal(event.schema_version, "0.1");
  validateEventId(event.event_id);
  validateEventType(event.event_type);
  dateTime(event.recorded_at);
  if (hasOwn(event, "effective_at") && event.effective_at !== null) {
    dateTime(event.effective_at);
  }
  validateActor(event.actor);
  boundedString(event.space_id, 512);
  boundedString(event.session_id, 512);
  if (!Number.isSafeInteger(event.sequence) || (event.sequence as number) < 0) {
    throw new LocalStoreError("invalid_input");
  }
  if (event.previous_event_id !== null) {
    validateEventId(event.previous_event_id);
  }
  validateProvider(event.provider);
  validateSubject(event.subject);
  validatePayload(event.payload, limits);
  oneOf(event.sensitivity, ["public", "internal", "private", "restricted"]);
  validateRetention(event.retention);
  if (hasOwn(event, "extensions")) validateExtensions(event.extensions);
}

function validateActor(value: unknown): void {
  const actor = exactObject(value, ["id", "kind"], ["display_name"]);
  boundedString(actor.id, 512);
  oneOf(actor.kind, ["human", "agent", "service", "device"]);
  if (hasOwn(actor, "display_name")) boundedString(actor.display_name, 256);
}

function validateEventType(value: unknown): void {
  boundedString(value, 256);
  if (!CORE_EVENT_TYPES.has(value) && !NAMESPACED_EVENT_TYPE.test(value)) {
    throw new LocalStoreError("invalid_input");
  }
}

function validateProvider(value: unknown): void {
  const provider = exactObject(
    value,
    ["name"],
    [
      "adapter_version",
      "provider_version",
      "external_session_id",
      "external_event_id",
    ],
  );
  stringMatching(provider.name, PROVIDER_NAME, 128);
  optionalBoundedString(provider, "adapter_version", 128);
  optionalBoundedString(provider, "provider_version", 128);
  optionalBoundedString(provider, "external_session_id", 512);
  optionalBoundedString(provider, "external_event_id", 512);
}

function validateSubject(value: unknown): void {
  const subject = exactObject(value, ["kind", "id"], []);
  stringMatching(subject.kind, SUBJECT_KIND, 128);
  boundedString(subject.id, 512);
}

function validatePayload(value: unknown, limits: StoreLimits): void {
  const payload = exactObject(
    value,
    ["media_type", "digest"],
    ["inline", "path"],
  );
  boundedString(payload.media_type, 256);
  if (!isDigest(payload.digest)) throw new LocalStoreError("invalid_input");
  const hasInline = hasOwn(payload, "inline");
  const hasPath = hasOwn(payload, "path");
  if (hasInline === hasPath) throw new LocalStoreError("invalid_input");
  if (hasInline) {
    let inlineBytes: Uint8Array;
    try {
      inlineBytes = canonicalJsonBytes(payload.inline, {
        maxDepth: limits.maxJsonDepth,
        maxStringBytes: limits.maxJsonStringBytes,
      });
    } catch (error) {
      throw new LocalStoreError(
        error instanceof RangeError ? "resource_limit" : "invalid_input",
      );
    }
    if (sha256Digest(inlineBytes) !== payload.digest) {
      throw new LocalStoreError("conflict");
    }
  } else if (!isSafeArchivePath(payload.path)) {
    throw new LocalStoreError("invalid_input");
  }
}

function validateRetention(value: unknown): void {
  const retention = exactObject(value, ["class", "expires_at"], []);
  oneOf(retention.class, ["ephemeral", "checkpoint", "archive", "legal-hold"]);
  if (retention.expires_at !== null) dateTime(retention.expires_at);
}

function validateExtensions(value: unknown): void {
  const extensions = exactObject(value, [], [], true);
  for (const key of Object.keys(extensions)) {
    if (!EXTENSION_KEY.test(key)) throw new LocalStoreError("invalid_input");
  }
}

function exactObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  allowAnyKeys = false,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new LocalStoreError("invalid_input");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new LocalStoreError("invalid_input");
  }
  const object = value as Record<string, unknown>;
  for (const key of required) {
    if (!hasOwn(object, key)) throw new LocalStoreError("invalid_input");
  }
  if (!allowAnyKeys) {
    const allowed = new Set([...required, ...optional]);
    if (Object.keys(object).some((key) => !allowed.has(key))) {
      throw new LocalStoreError("invalid_input");
    }
  }
  return object;
}

function hasOwn(object: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function optionalBoundedString(
  object: Record<string, unknown>,
  key: string,
  maxLength: number,
): void {
  if (hasOwn(object, key)) boundedString(object[key], maxLength);
}

function boundedString(
  value: unknown,
  maxLength: number,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength
  ) {
    throw new LocalStoreError("invalid_input");
  }
}

function stringMatching(
  value: unknown,
  pattern: RegExp,
  maxLength: number,
): asserts value is string {
  boundedString(value, maxLength);
  if (!pattern.test(value)) throw new LocalStoreError("invalid_input");
}

function dateTime(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length > 128) {
    throw new LocalStoreError("invalid_input");
  }
  const match = RFC3339_DATE_TIME.exec(value);
  if (!match) throw new LocalStoreError("invalid_input");

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
    throw new LocalStoreError("invalid_input");
  }
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function equal(value: unknown, expected: unknown): void {
  if (value !== expected) throw new LocalStoreError("invalid_input");
}

function oneOf(value: unknown, expected: readonly string[]): void {
  if (typeof value !== "string" || !expected.includes(value)) {
    throw new LocalStoreError("invalid_input");
  }
}

function deepFreeze(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  for (const key of Object.keys(value)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return Object.freeze(value);
}
