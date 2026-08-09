const textEncoder = new TextEncoder();

export interface CanonicalJsonLimits {
  readonly maxDepth: number;
  readonly maxStringBytes: number;
}

const DEFAULT_CANONICAL_LIMITS: CanonicalJsonLimits = {
  maxDepth: 128,
  maxStringBytes: 8 * 1024 * 1024,
};

/**
 * RFC 8785/JCS canonical JSON for the JSON-compatible value subset accepted by
 * this module. Objects must be plain data objects, arrays must be dense, all
 * numbers must be finite IEEE-754 values, and strings must be valid Unicode.
 */
export function canonicalizeJson(
  value: unknown,
  limits: Partial<CanonicalJsonLimits> = {},
): string {
  const resolved = { ...DEFAULT_CANONICAL_LIMITS, ...limits };
  assertPositiveInteger(resolved.maxDepth, "maxDepth");
  assertPositiveInteger(resolved.maxStringBytes, "maxStringBytes");
  return serialize(value, resolved, 0, new WeakSet<object>());
}

export function canonicalJsonBytes(
  value: unknown,
  limits: Partial<CanonicalJsonLimits> = {},
): Uint8Array {
  return textEncoder.encode(canonicalizeJson(value, limits));
}

function serialize(
  value: unknown,
  limits: CanonicalJsonLimits,
  depth: number,
  ancestors: WeakSet<object>,
): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("Canonical JSON rejects non-finite numbers.");
      }
      return Object.is(value, -0) ? "0" : String(value);
    case "string":
      assertUnicodeString(value, limits.maxStringBytes);
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError("Value is outside the supported JSON data model.");
  }

  if (depth >= limits.maxDepth) {
    throw new RangeError(
      "Canonical JSON nesting exceeds the configured limit.",
    );
  }
  if (ancestors.has(value)) {
    throw new TypeError("Canonical JSON rejects cyclic objects.");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return serializeArray(value, limits, depth + 1, ancestors);
    }
    return serializeObject(value, limits, depth + 1, ancestors);
  } finally {
    ancestors.delete(value);
  }
}

function serializeArray(
  value: readonly unknown[],
  limits: CanonicalJsonLimits,
  depth: number,
  ancestors: WeakSet<object>,
): string {
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key)),
    )
  ) {
    throw new TypeError("Canonical JSON arrays may only contain indexed data.");
  }

  const parts: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Canonical JSON rejects sparse or accessor arrays.");
    }
    parts.push(serialize(descriptor.value, limits, depth, ancestors));
  }
  return `[${parts.join(",")}]`;
}

function serializeObject(
  value: object,
  limits: CanonicalJsonLimits,
  depth: number,
  ancestors: WeakSet<object>,
): string {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Canonical JSON requires a plain data object.");
  }

  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new TypeError("Canonical JSON rejects symbol properties.");
  }

  const keys = (ownKeys as string[]).sort();
  const parts: string[] = [];
  for (const key of keys) {
    assertUnicodeString(key, limits.maxStringBytes);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(
        "Canonical JSON requires enumerable data-only properties.",
      );
    }
    parts.push(
      `${JSON.stringify(key)}:${serialize(descriptor.value, limits, depth, ancestors)}`,
    );
  }
  return `{${parts.join(",")}}`;
}

function assertUnicodeString(value: string, maxBytes: number): void {
  if (textEncoder.encode(value).byteLength > maxBytes) {
    throw new RangeError("JSON string exceeds the configured byte limit.");
  }

  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("Canonical JSON rejects lone UTF-16 surrogates.");
      }
      index += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("Canonical JSON rejects lone UTF-16 surrogates.");
    }
  }
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer.`);
  }
}
