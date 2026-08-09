const textEncoder = new TextEncoder();

export interface CanonicalJsonLimits {
  readonly maxDepth: number;
  readonly maxStringBytes: number;
}

const DEFAULT_LIMITS: CanonicalJsonLimits = {
  maxDepth: 128,
  maxStringBytes: 8 * 1024 * 1024,
};

/** Independent RFC 8785 serialization for the JSON data model. */
export function canonicalJsonBytes(
  value: unknown,
  limits: Partial<CanonicalJsonLimits> = {},
): Uint8Array {
  const resolved = { ...DEFAULT_LIMITS, ...limits };
  assertPositiveInteger(resolved.maxDepth, "maxDepth");
  assertPositiveInteger(resolved.maxStringBytes, "maxStringBytes");
  return textEncoder.encode(
    serialize(value, resolved, 0, new WeakSet<object>()),
  );
}

function serialize(
  value: unknown,
  limits: CanonicalJsonLimits,
  depth: number,
  ancestors: WeakSet<object>,
): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("RFC 8785 does not permit non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertUnicodeString(value, limits.maxStringBytes);
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new TypeError("Value is outside the JSON data model.");
  }
  if (depth >= limits.maxDepth) {
    throw new RangeError(
      "Canonical JSON nesting exceeds the configured limit.",
    );
  }
  if (ancestors.has(value)) {
    throw new TypeError("Canonical JSON does not permit cyclic objects.");
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

  const items: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Canonical JSON does not permit sparse arrays.");
    }
    items.push(serialize(descriptor.value, limits, depth, ancestors));
  }
  return `[${items.join(",")}]`;
}

function serializeObject(
  value: object,
  limits: CanonicalJsonLimits,
  depth: number,
  ancestors: WeakSet<object>,
): string {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Canonical JSON requires plain data objects.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new TypeError("Canonical JSON does not permit symbol keys.");
  }

  const members: string[] = [];
  for (const key of (ownKeys as string[]).sort()) {
    assertUnicodeString(key, limits.maxStringBytes);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(
        "Canonical JSON requires enumerable data properties.",
      );
    }
    members.push(
      `${JSON.stringify(key)}:${serialize(descriptor.value, limits, depth, ancestors)}`,
    );
  }
  return `{${members.join(",")}}`;
}

function assertUnicodeString(value: string, maxBytes: number): void {
  if (textEncoder.encode(value).byteLength > maxBytes) {
    throw new RangeError("JSON string exceeds the configured byte limit.");
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("JSON contains a lone UTF-16 surrogate.");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("JSON contains a lone UTF-16 surrogate.");
    }
  }
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer.`);
  }
}
