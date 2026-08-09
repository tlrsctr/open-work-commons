export interface SafeJsonLimits {
  readonly maxDepth: number;
  readonly maxStringBytes: number;
}

export class SafeJsonError extends Error {
  constructor(
    readonly kind: "syntax" | "duplicate-key" | "resource-limit",
    message: string,
  ) {
    super(message);
    this.name = "SafeJsonError";
  }
}

/**
 * Parses UTF-8 JSON without hooks, dynamic evaluation, or network access.
 * Unlike JSON.parse, this parser rejects duplicate object keys. Objects have a
 * null prototype so keys such as `__proto__` remain inert data.
 */
export function parseJsonSafely(
  bytes: Uint8Array,
  limits: SafeJsonLimits,
): unknown {
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 1) {
    throw new RangeError("maxDepth must be a positive safe integer.");
  }
  if (
    !Number.isSafeInteger(limits.maxStringBytes) ||
    limits.maxStringBytes < 1
  ) {
    throw new RangeError("maxStringBytes must be a positive safe integer.");
  }
  if (
    bytes.byteLength >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    throw new SafeJsonError("syntax", "A UTF-8 BOM is not permitted.");
  }

  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new SafeJsonError("syntax", "Input is not valid UTF-8.");
  }

  return new Parser(source, limits).parse();
}

class Parser {
  private index = 0;

  constructor(
    private readonly source: string,
    private readonly limits: SafeJsonLimits,
  ) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.source.length) this.syntax();
    return value;
  }

  private parseValue(depth: number): unknown {
    const character = this.source[this.index];
    switch (character) {
      case "{":
        return this.parseObject(depth + 1);
      case "[":
        return this.parseArray(depth + 1);
      case '"':
        return this.parseString();
      case "t":
        return this.parseLiteral("true", true);
      case "f":
        return this.parseLiteral("false", false);
      case "n":
        return this.parseLiteral("null", null);
      default:
        if (character === "-" || (character && /[0-9]/.test(character))) {
          return this.parseNumber();
        }
        this.syntax();
    }
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.assertDepth(depth);
    this.index += 1;
    this.skipWhitespace();
    const output: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    const keys = new Set<string>();
    if (this.consume("}")) return output;

    while (true) {
      if (this.source[this.index] !== '"') this.syntax();
      const key = this.parseString();
      if (keys.has(key)) {
        throw new SafeJsonError(
          "duplicate-key",
          "JSON object contains a duplicate key.",
        );
      }
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.syntax();
      this.skipWhitespace();
      output[key] = this.parseValue(depth);
      this.skipWhitespace();
      if (this.consume("}")) return output;
      if (!this.consume(",")) this.syntax();
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): unknown[] {
    this.assertDepth(depth);
    this.index += 1;
    this.skipWhitespace();
    const output: unknown[] = [];
    if (this.consume("]")) return output;

    while (true) {
      output.push(this.parseValue(depth));
      this.skipWhitespace();
      if (this.consume("]")) return output;
      if (!this.consume(",")) this.syntax();
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      // A decoded JSON string can consume at most six source characters per
      // Unicode code unit (`\uXXXX`). Reject larger tokens before JSON.parse
      // allocates the decoded value.
      if (this.index - start > this.limits.maxStringBytes * 6 + 2) {
        throw new SafeJsonError(
          "resource-limit",
          "JSON string exceeds the configured byte limit.",
        );
      }
      const code = this.source.charCodeAt(this.index);
      if (!escaped && code === 0x22) {
        this.index += 1;
        const token = this.source.slice(start, this.index);
        let value: unknown;
        try {
          value = JSON.parse(token) as unknown;
        } catch {
          this.syntax();
        }
        if (typeof value !== "string") this.syntax();
        assertValidUnicode(value);
        if (Buffer.byteLength(value, "utf8") > this.limits.maxStringBytes) {
          throw new SafeJsonError(
            "resource-limit",
            "JSON string exceeds the configured byte limit.",
          );
        }
        return value;
      }
      if (!escaped && code < 0x20) this.syntax();
      if (!escaped && code === 0x5c) {
        escaped = true;
      } else {
        escaped = false;
      }
      this.index += 1;
    }
    this.syntax();
  }

  private parseNumber(): number {
    const remaining = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      remaining,
    );
    if (!match) this.syntax();
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) {
      throw new SafeJsonError(
        "syntax",
        "JSON number is outside the finite IEEE-754 range.",
      );
    }
    return value;
  }

  private parseLiteral<T>(literal: string, value: T): T {
    if (!this.source.startsWith(literal, this.index)) this.syntax();
    this.index += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (
      this.source[this.index] === " " ||
      this.source[this.index] === "\n" ||
      this.source[this.index] === "\r" ||
      this.source[this.index] === "\t"
    ) {
      this.index += 1;
    }
  }

  private consume(character: string): boolean {
    if (this.source[this.index] !== character) return false;
    this.index += 1;
    return true;
  }

  private assertDepth(depth: number): void {
    if (depth > this.limits.maxDepth) {
      throw new SafeJsonError(
        "resource-limit",
        "JSON nesting exceeds the configured limit.",
      );
    }
  }

  private syntax(): never {
    throw new SafeJsonError("syntax", "Input is not valid JSON.");
  }
}

function assertValidUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new SafeJsonError(
          "syntax",
          "JSON contains a lone UTF-16 surrogate.",
        );
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new SafeJsonError(
        "syntax",
        "JSON contains a lone UTF-16 surrogate.",
      );
    }
  }
}
