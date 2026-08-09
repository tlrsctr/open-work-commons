import { createHash } from "node:crypto";

import type { Digest } from "./types.js";

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Digest(bytes: Uint8Array): Digest {
  return `sha256:${sha256Hex(bytes)}`;
}

export function eventStorageKey(eventId: string): string {
  return sha256Hex(Buffer.from(eventId, "utf8"));
}

export function blobRelativePath(digest: Digest): string {
  const hex = digest.slice("sha256:".length);
  return `blobs/sha256/${hex.slice(0, 2)}/${hex.slice(2)}`;
}
