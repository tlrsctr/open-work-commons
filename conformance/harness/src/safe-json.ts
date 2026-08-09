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

/** Strict UTF-8 JSON parser with duplicate-key and resource-limit checks. */
export function parseJsonSafely(
  bytes: Uint8Array,
  limits: SafeJsonLimits,
): unknown {
  assertLimit(limits.maxDepth, "maxDepth");
  assertLimit(limits.maxStringBytes, "maxStringBytes");
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
    const token = this.source[this.index];
    if (token === "{") return this.parseObject(depth + 1);
    if (token === "[") return this.parseArray(depth + 1);
    if (token === '"') return this.parseString();
    if (token === "t") return this.parseLiteral("true", true);
    if (token === "f") return this.parseLiteral("false", false);
    if (token === "n") return this.parseLiteral("null", null);
    if (token === "-" || (token !== undefined && /[0-9]/.test(token))) {
      return this.parseNumber();
    }
    return this.syntax();
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.assertDepth(depth);
    this.index += 1;
    this.skipWhitespace();
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    if (this.consume("}")) return result;

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
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: this.parseValue(depth),
        writable: true,
      });
      this.skipWhitespace();
      if (this.consume("}")) return result;
      if (!this.consume(",")) this.syntax();
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): unknown[] {
    this.assertDepth(depth);
    this.index += 1;
    this.skipWhitespace();
    const result: unknown[] = [];
    if (this.consume("]")) return result;

    while (true) {
      result.push(this.parseValue(depth));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      if (!this.consume(",")) this.syntax();
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (!escaped && code === 0x22) {
        this.index += 1;
        let value: unknown;
        try {
          value = JSON.parse(this.source.slice(start, this.index)) as unknown;
        } catch {
          return this.syntax();
        }
        if (typeof value !== "string") return this.syntax();
        assertUnicode(value);
        if (Buffer.byteLength(value, "utf8") > this.limits.maxStringBytes) {
          throw new SafeJsonError(
            "resource-limit",
            "JSON string exceeds the configured byte limit.",
          );
        }
        return value;
      }
      if (!escaped && code < 0x20) return this.syntax();
      if (!escaped && code === 0x5c) escaped = true;
      else escaped = false;
      this.index += 1;
    }
    return this.syntax();
  }

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.source.slice(this.index),
    );
    if (!match) return this.syntax();
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) return this.syntax();
    return value;
  }

  private parseLiteral<T>(token: string, value: T): T {
    if (!this.source.startsWith(token, this.index)) return this.syntax();
    this.index += token.length;
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

  private consume(token: string): boolean {
    if (this.source[this.index] !== token) return false;
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

function assertUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new SafeJsonError("syntax", "JSON contains invalid Unicode.");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new SafeJsonError("syntax", "JSON contains invalid Unicode.");
    }
  }
}

function assertLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer.`);
  }
}
