import { GitStateCaptureError } from "./types.js";

const MAGIC = Buffer.from("OWC-GIT-PATCH\0", "ascii");
const VERSION = 1;
const SECTION_NAMES = ["index.diff", "worktree.diff"] as const;

export interface GitPatchSections {
  readonly index: Uint8Array;
  readonly worktree: Uint8Array;
}

export function encodeGitPatchArtifact(
  sections: GitPatchSections,
  maximumBytes: number,
): Uint8Array {
  const payloads = [
    Buffer.from(sections.index),
    Buffer.from(sections.worktree),
  ];
  const headerBytes =
    MAGIC.byteLength +
    2 +
    SECTION_NAMES.reduce(
      (total, name) => total + 2 + Buffer.byteLength(name, "utf8") + 8,
      0,
    );
  const totalBytes = payloads.reduce(
    (total, payload) => total + payload.byteLength,
    headerBytes,
  );

  if (totalBytes > maximumBytes) {
    throw new GitStateCaptureError(
      "OUTPUT_LIMIT_EXCEEDED",
      "The framed Git patch exceeded the configured byte limit.",
    );
  }

  const output = Buffer.allocUnsafe(totalBytes);
  let offset = 0;
  offset += MAGIC.copy(output, offset);
  output.writeUInt8(VERSION, offset++);
  output.writeUInt8(SECTION_NAMES.length, offset++);

  for (let index = 0; index < SECTION_NAMES.length; index++) {
    const name = Buffer.from(SECTION_NAMES[index] ?? "", "utf8");
    const payload = payloads[index] ?? Buffer.alloc(0);
    output.writeUInt16BE(name.byteLength, offset);
    offset += 2;
    offset += name.copy(output, offset);
    output.writeBigUInt64BE(BigInt(payload.byteLength), offset);
    offset += 8;
    offset += payload.copy(output, offset);
  }

  return output;
}

export function decodeGitPatchArtifact(bytes: Uint8Array): GitPatchSections {
  const input = Buffer.from(bytes);
  let offset = 0;
  if (
    input.byteLength < MAGIC.byteLength + 2 ||
    !input.subarray(0, MAGIC.byteLength).equals(MAGIC)
  ) {
    throw invalidPatch();
  }
  offset += MAGIC.byteLength;
  if (input.readUInt8(offset++) !== VERSION) throw invalidPatch();
  if (input.readUInt8(offset++) !== SECTION_NAMES.length) throw invalidPatch();

  const sections = new Map<string, Uint8Array>();
  for (const expectedName of SECTION_NAMES) {
    if (offset + 2 > input.byteLength) throw invalidPatch();
    const nameLength = input.readUInt16BE(offset);
    offset += 2;
    if (offset + nameLength + 8 > input.byteLength) throw invalidPatch();
    const name = input.subarray(offset, offset + nameLength).toString("utf8");
    offset += nameLength;
    if (name !== expectedName || sections.has(name)) throw invalidPatch();
    const payloadLength = input.readBigUInt64BE(offset);
    offset += 8;
    if (payloadLength > BigInt(Number.MAX_SAFE_INTEGER)) throw invalidPatch();
    const end = offset + Number(payloadLength);
    if (end > input.byteLength) throw invalidPatch();
    sections.set(name, input.subarray(offset, end));
    offset = end;
  }

  if (offset !== input.byteLength) throw invalidPatch();
  return {
    index: sections.get("index.diff") ?? Buffer.alloc(0),
    worktree: sections.get("worktree.diff") ?? Buffer.alloc(0),
  };
}

function invalidPatch(): GitStateCaptureError {
  return new GitStateCaptureError(
    "AMBIGUOUS_GIT_OUTPUT",
    "The OWC Git patch artifact is malformed.",
  );
}
