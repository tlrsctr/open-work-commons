import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  type KeyObject,
} from "node:crypto";

import { canonicalJsonBytes } from "../../harness/src/canonical-json.js";
import {
  goldenFixtureRoot,
  loadGoldenFixture,
} from "../../harness/src/harness.js";
import { sha256 } from "../../harness/src/crypto.js";
import { parseJsonSafely } from "../../harness/src/safe-json.js";
import type {
  LogicalArchive,
  LogicalMember,
  LogicalMemberKind,
} from "./model.js";

const FIXTURE_JSON_LIMITS = {
  maxDepth: 128,
  maxStringBytes: 8 * 1024 * 1024,
} as const;

const CORPUS_PRIVATE_SEED = Buffer.from(
  "5a7c749d6c34a69e4701c87cf5364ee8e5033850c0b30f8ff38e55cc9115d7c1",
  "hex",
);

const CORPUS_PRIVATE_KEY = privateKeyFromSeed(CORPUS_PRIVATE_SEED);
const CORPUS_PUBLIC_KEY = publicKeyBase64Url(CORPUS_PRIVATE_KEY);
export const corpusSignerFingerprint = fingerprint(CORPUS_PUBLIC_KEY);

export type JsonObject = Record<string, unknown>;

export async function loadGoldenLogicalArchive(): Promise<LogicalArchive> {
  const fixture = await loadGoldenFixture(goldenFixtureRoot);
  const members = [...fixture.entryBytes.entries()].map(
    ([logicalPath, bytes]): LogicalMember => ({
      logicalPath,
      kind: "file",
      bytes: Buffer.from(bytes),
    }),
  );

  return {
    manifestBytes: Buffer.from(fixture.manifestBytes),
    members,
    trustAnchors: new Set([fingerprint(fixture.manifest.signature.public_key)]),
  };
}

export function cloneArchive(archive: LogicalArchive): LogicalArchive {
  return {
    manifestBytes: Buffer.from(archive.manifestBytes),
    members: archive.members.map((member) => ({
      logicalPath: member.logicalPath,
      kind: member.kind,
      bytes: Buffer.from(member.bytes),
    })),
    trustAnchors: new Set(archive.trustAnchors),
  };
}

export function parseObject(bytes: Uint8Array): JsonObject {
  const parsed = parseJsonSafely(bytes, FIXTURE_JSON_LIMITS);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TypeError("Expected a JSON object.");
  }
  return toPlainJson(parsed) as JsonObject;
}

export function encodeObject(value: JsonObject): Uint8Array {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export function manifestObject(archive: LogicalArchive): JsonObject {
  return parseObject(archive.manifestBytes);
}

export function memberObject(
  archive: LogicalArchive,
  logicalPath: string,
): JsonObject {
  const member = archive.members.find(
    (candidate) => candidate.logicalPath === logicalPath,
  );
  if (!member) throw new Error(`Missing fixture member: ${logicalPath}`);
  return parseObject(member.bytes);
}

export function replaceManifest(
  archive: LogicalArchive,
  manifest: JsonObject,
): LogicalArchive {
  return { ...archive, manifestBytes: encodeObject(manifest) };
}

export function replaceMember(
  archive: LogicalArchive,
  logicalPath: string,
  bytes: Uint8Array,
  kind: LogicalMemberKind = "file",
): LogicalArchive {
  let replaced = false;
  const members = archive.members.map((member) => {
    if (!replaced && member.logicalPath === logicalPath) {
      replaced = true;
      return { logicalPath, kind, bytes: Buffer.from(bytes) };
    }
    return member;
  });
  if (!replaced) throw new Error(`Missing fixture member: ${logicalPath}`);
  return { ...archive, members };
}

export function addMember(
  archive: LogicalArchive,
  logicalPath: string,
  bytes: Uint8Array,
  kind: LogicalMemberKind = "file",
): LogicalArchive {
  return {
    ...archive,
    members: [
      ...archive.members,
      { logicalPath, kind, bytes: Buffer.from(bytes) },
    ],
  };
}

export function removeMember(
  archive: LogicalArchive,
  logicalPath: string,
): LogicalArchive {
  return {
    ...archive,
    members: archive.members.filter(
      (member) => member.logicalPath !== logicalPath,
    ),
  };
}

export function replaceMemberPath(
  archive: LogicalArchive,
  from: string,
  to: string,
): LogicalArchive {
  let replaced = false;
  const members = archive.members.map((member) => {
    if (!replaced && member.logicalPath === from) {
      replaced = true;
      return { ...member, logicalPath: to };
    }
    return member;
  });
  if (!replaced) throw new Error(`Missing fixture member: ${from}`);
  return { ...archive, members };
}

export function replaceMemberKind(
  archive: LogicalArchive,
  logicalPath: string,
  kind: LogicalMemberKind,
): LogicalArchive {
  const member = archive.members.find(
    (candidate) => candidate.logicalPath === logicalPath,
  );
  if (!member) throw new Error(`Missing fixture member: ${logicalPath}`);
  return replaceMember(archive, logicalPath, member.bytes, kind);
}

export function updateManifestEntry(
  archive: LogicalArchive,
  logicalPath: string,
): LogicalArchive {
  const manifest = manifestObject(archive);
  const entries = manifest.entries as JsonObject[];
  const entry = entries.find((candidate) => candidate.path === logicalPath);
  const member = archive.members.find(
    (candidate) => candidate.logicalPath === logicalPath,
  );
  if (!entry || !member) {
    throw new Error(`Cannot refresh missing fixture entry: ${logicalPath}`);
  }
  entry.byte_length = member.bytes.byteLength;
  entry.digest = sha256(member.bytes);
  return replaceManifest(archive, manifest);
}

export function addManifestEntry(
  archive: LogicalArchive,
  entry: JsonObject,
): LogicalArchive {
  const manifest = manifestObject(archive);
  const entries = manifest.entries as JsonObject[];
  entries.push(structuredClone(entry));
  entries.sort((left, right) =>
    compareCodeUnits(String(left.path), String(right.path)),
  );
  return replaceManifest(archive, manifest);
}

export function refreshManifestLimits(archive: LogicalArchive): LogicalArchive {
  const manifest = manifestObject(archive);
  const entries = manifest.entries as JsonObject[];
  const byPath = uniqueFileMembers(archive);
  const lengths = entries.map((entry) => {
    const member = byPath.get(String(entry.path));
    if (!member)
      throw new Error(`Cannot measure fixture entry: ${String(entry.path)}`);
    return member.bytes.byteLength;
  });
  manifest.limits = {
    entry_count: entries.length,
    expanded_bytes: lengths.reduce((total, length) => total + length, 0),
    max_entry_bytes: Math.max(...lengths),
  };
  return replaceManifest(archive, manifest);
}

export function refreshRootCheckpoint(archive: LogicalArchive): LogicalArchive {
  const manifest = manifestObject(archive);
  const root = manifest.root_checkpoint as JsonObject;
  const path = String(root.path);
  const descriptor = (manifest.entries as JsonObject[]).find(
    (entry) => entry.path === path,
  );
  if (!descriptor) throw new Error("Missing root checkpoint descriptor.");
  root.digest = descriptor.digest;
  return replaceManifest(archive, manifest);
}

export function resignArchive(
  archive: LogicalArchive,
  options: { readonly trustCorpusSigner: boolean },
): LogicalArchive {
  const manifest = manifestObject(archive);
  const signature = manifest.signature as JsonObject;
  signature.canonicalization = "RFC8785";
  signature.digest_algorithm = "sha256";
  signature.signature_algorithm = "ed25519";
  signature.key_id = `urn:owc:key:ed25519:${corpusSignerFingerprint.slice("sha256:".length)}`;
  signature.public_key = CORPUS_PUBLIC_KEY;
  delete signature.payload_digest;
  delete signature.value;
  const canonical = canonicalJsonBytes(manifest);
  signature.payload_digest = sha256(canonical);
  signature.value = sign(null, canonical, CORPUS_PRIVATE_KEY).toString(
    "base64url",
  );
  const trustAnchors = new Set(archive.trustAnchors);
  if (options.trustCorpusSigner) trustAnchors.add(corpusSignerFingerprint);
  else trustAnchors.delete(corpusSignerFingerprint);
  return {
    ...archive,
    manifestBytes: encodeObject(manifest),
    trustAnchors,
  };
}

export function refreshCheckpointArchive(
  archive: LogicalArchive,
  checkpoint: JsonObject,
): LogicalArchive {
  let next = replaceMember(
    archive,
    "checkpoints/checkpoint.json",
    encodeObject(checkpoint),
  );
  next = updateManifestEntry(next, "checkpoints/checkpoint.json");
  next = refreshRootCheckpoint(next);
  next = refreshManifestLimits(next);
  return next;
}

export function refreshEventArchive(
  archive: LogicalArchive,
  event: JsonObject,
): LogicalArchive {
  let next = replaceMember(
    archive,
    "events/session-started.json",
    encodeObject(event),
  );
  next = updateManifestEntry(next, "events/session-started.json");
  const checkpoint = memberObject(next, "checkpoints/checkpoint.json");
  const reference = (checkpoint.event_refs as JsonObject[])[0];
  const entry = (manifestObject(next).entries as JsonObject[]).find(
    (candidate) => candidate.path === "events/session-started.json",
  );
  if (!reference || !entry) throw new Error("Missing event fixture reference.");
  reference.digest = entry.digest;
  next = refreshCheckpointArchive(next, checkpoint);
  return next;
}

export function fingerprint(publicKey: string): `sha256:${string}` {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(publicKey, "base64url"))
    .digest("hex")}`;
}

function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([prefix, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyBase64Url(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Missing Ed25519 public key.");
  return jwk.x;
}

function uniqueFileMembers(
  archive: LogicalArchive,
): ReadonlyMap<string, LogicalMember> {
  return new Map(
    archive.members
      .filter((member) => member.kind === "file")
      .map((member) => [member.logicalPath, member]),
  );
}

function compareCodeUnits(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function toPlainJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(toPlainJson);
  if (typeof value !== "object" || value === null) return value;
  const result: JsonObject = {};
  for (const [key, child] of Object.entries(value)) {
    Object.defineProperty(result, key, {
      configurable: true,
      enumerable: true,
      value: toPlainJson(child),
      writable: true,
    });
  }
  return result;
}
