import { canonicalJsonBytes } from "../../harness/src/canonical-json.js";
import { sha256, verifyEd25519 } from "../../harness/src/crypto.js";
import {
  compileLocalSchemas,
  type ArchiveEntry,
  type SchemaName,
} from "../../harness/src/harness.js";
import { isSafeArchivePath } from "../../harness/src/path.js";
import { parseJsonSafely, SafeJsonError } from "../../harness/src/safe-json.js";
import { fingerprint, type JsonObject } from "./builder.js";
import {
  CorpusFailure,
  defaultOracleLimits,
  type LogicalArchive,
  type LogicalMember,
  type OracleLimits,
  type OracleSuccess,
} from "./model.js";

interface ManifestEntry extends ArchiveEntry {
  readonly media_type: string;
}

interface Manifest extends JsonObject {
  readonly root_checkpoint: {
    readonly checkpoint_id: string;
    readonly path: string;
    readonly digest: string;
  };
  readonly entries: readonly ManifestEntry[];
  readonly signature: {
    readonly public_key: string;
    readonly payload_digest: string;
    readonly value: string;
  };
}

interface ObjectReference {
  readonly path: string;
  readonly digest: string;
}

interface Checkpoint extends JsonObject {
  readonly checkpoint_id: string;
  readonly session_id: string;
  readonly parents: readonly (ObjectReference & {
    readonly checkpoint_id: string;
  })[];
  readonly event_refs: readonly (ObjectReference & {
    readonly event_id: string;
  })[];
  readonly git_state: ObjectReference;
  readonly artifacts: readonly ObjectReference[];
  readonly evidence: readonly (JsonObject & {
    readonly source?: ObjectReference;
  })[];
}

const ROLE_SCHEMAS: Readonly<
  Partial<Record<ArchiveEntry["role"], SchemaName>>
> = {
  checkpoint: "checkpoint",
  event: "event",
  evidence: "evidence",
  "git-state": "gitState",
};

export async function verifyWithIndependentOracle(
  archive: LogicalArchive,
  limits: OracleLimits = defaultOracleLimits,
): Promise<OracleSuccess> {
  enforcePositiveLimits(limits);
  const packedBytes =
    archive.manifestBytes.byteLength +
    archive.members.reduce(
      (total, member) => total + member.bytes.byteLength,
      0,
    );
  if (packedBytes > limits.maxPackedBytes) {
    fail("resource-packed-bytes", "archive.container");
  }

  const manifest = parseSignedObject(
    archive.manifestBytes,
    limits,
    "archive.manifest",
  ) as unknown as Manifest;
  const entries = requireEntries(manifest);

  checkContainerMembers(archive.members);
  checkManifestPaths(entries);
  if (
    entries.length > limits.maxEntryCount ||
    archive.members.length > limits.maxEntryCount
  ) {
    fail("resource-entry-count", "archive.container");
  }

  const members = indexMembers(archive.members);
  let expandedBytes = 0;
  for (const [index, entry] of entries.entries()) {
    const affectedObject = entryObject(index, entry.path);
    const member = members.get(entry.path);
    if (!member) fail("missing-entry", affectedObject);
    if (member.bytes.byteLength > limits.maxEntryBytes) {
      fail("resource-entry-bytes", affectedObject);
    }
    expandedBytes += member.bytes.byteLength;
  }
  if (expandedBytes > limits.maxExpandedBytes) {
    fail("resource-expanded-bytes", "archive.entries");
  }

  const schemas = await compileLocalSchemas();
  if (!schemas.validate("archiveManifest", manifest).valid) {
    fail("invalid-schema", "archive.manifest");
  }

  for (const [index, entry] of entries.entries()) {
    const member = members.get(entry.path);
    if (!member) fail("missing-entry", entryObject(index, entry.path));
    if (member.bytes.byteLength !== entry.byte_length) {
      fail("entry-byte-length", entryObject(index, entry.path));
    }
    if (sha256(member.bytes) !== entry.digest) {
      fail("entry-digest", entryObject(index, entry.path));
    }
  }

  verifyManifestSignature(manifest);

  const parsedEntries = new Map<string, JsonObject>();
  for (const [index, entry] of entries.entries()) {
    const schemaName = ROLE_SCHEMAS[entry.role];
    if (!schemaName) continue;
    const member = members.get(entry.path);
    if (!member) fail("missing-entry", entryObject(index, entry.path));
    const object = parseSignedObject(
      member.bytes,
      limits,
      entryObject(index, entry.path),
    );
    if (!schemas.validate(schemaName, object).valid) {
      fail("invalid-schema", entryObject(index, entry.path));
    }
    parsedEntries.set(entry.path, object);
  }

  const descriptors = new Map(entries.map((entry) => [entry.path, entry]));
  const rootCheckpoint = resolveRootCheckpoint(
    manifest,
    descriptors,
    members,
    parsedEntries,
  );
  verifyCheckpointGraph(
    manifest.root_checkpoint.path,
    rootCheckpoint,
    descriptors,
    members,
    parsedEntries,
  );
  verifyCheckpointReferences(
    rootCheckpoint,
    descriptors,
    members,
    parsedEntries,
  );

  const signerFingerprint = fingerprint(manifest.signature.public_key);
  if (!archive.trustAnchors.has(signerFingerprint)) {
    fail("untrusted-signer", "archive.signer");
  }

  const verifiedEntries = entries.map((entry) => entry.path);
  const untrustedContent = collectUntrustedContent(entries, parsedEntries);
  return {
    integrityValid: true,
    signerTrusted: true,
    verifiedEntries,
    resumeEligibleEntries: verifiedEntries,
    ignoredEntryCount: archive.members.length - entries.length,
    untrustedContent,
  };
}

function checkContainerMembers(members: readonly LogicalMember[]): void {
  const paths = new Set<string>();
  for (const [index, member] of members.entries()) {
    if (!isSafeArchivePath(member.logicalPath)) {
      fail("unsafe-path", `container.members[${index}].path`);
    }
    if (paths.has(member.logicalPath)) {
      fail("duplicate-logical-path", `container.members[${index}].path`);
    }
    paths.add(member.logicalPath);
    if (member.kind !== "file") {
      fail("unsafe-entry-kind", `container.members[${index}].kind`);
    }
  }
}

function checkManifestPaths(entries: readonly ManifestEntry[]): void {
  const paths = new Set<string>();
  for (const [index, entry] of entries.entries()) {
    if (!isSafeArchivePath(entry.path)) {
      fail("unsafe-path", `manifest.entries[${index}].path`);
    }
    if (paths.has(entry.path)) {
      fail("duplicate-manifest-path", `manifest.entries[${index}].path`);
    }
    paths.add(entry.path);
  }
}

function verifyManifestSignature(manifest: Manifest): void {
  const projection = structuredClone(manifest) as JsonObject;
  const signature = projection.signature;
  if (
    typeof signature !== "object" ||
    signature === null ||
    Array.isArray(signature)
  ) {
    fail("invalid-schema", "archive.manifest.signature");
  }
  delete (signature as JsonObject).payload_digest;
  delete (signature as JsonObject).value;
  const canonical = canonicalJsonBytes(projection);
  if (sha256(canonical) !== manifest.signature.payload_digest) {
    fail(
      "signature-payload-digest",
      "archive.manifest.signature.payload_digest",
    );
  }
  if (
    !verifyEd25519(
      canonical,
      manifest.signature.value,
      manifest.signature.public_key,
    )
  ) {
    fail("signature-invalid", "archive.manifest.signature.value");
  }
}

function resolveRootCheckpoint(
  manifest: Manifest,
  descriptors: ReadonlyMap<string, ManifestEntry>,
  members: ReadonlyMap<string, LogicalMember>,
  parsed: ReadonlyMap<string, JsonObject>,
): Checkpoint {
  const root = manifest.root_checkpoint;
  const descriptor = descriptors.get(root.path);
  const member = members.get(root.path);
  if (!descriptor || descriptor.role !== "checkpoint" || !member) {
    fail("reference-missing", "manifest.root_checkpoint");
  }
  if (
    root.digest !== descriptor.digest ||
    root.digest !== sha256(member.bytes)
  ) {
    fail("root-checkpoint-digest", "manifest.root_checkpoint.digest");
  }
  const checkpoint = parsed.get(root.path) as Checkpoint | undefined;
  if (!checkpoint || checkpoint.checkpoint_id !== root.checkpoint_id) {
    fail("root-checkpoint-identity", "manifest.root_checkpoint.checkpoint_id");
  }
  return checkpoint;
}

function verifyCheckpointGraph(
  rootPath: string,
  root: Checkpoint,
  descriptors: ReadonlyMap<string, ManifestEntry>,
  members: ReadonlyMap<string, LogicalMember>,
  parsed: ReadonlyMap<string, JsonObject>,
): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (path: string, checkpoint: Checkpoint): void => {
    if (visiting.has(checkpoint.checkpoint_id)) {
      fail("checkpoint-parent-cycle", "checkpoint.parents");
    }
    if (visited.has(checkpoint.checkpoint_id)) return;
    visiting.add(checkpoint.checkpoint_id);

    for (const parent of checkpoint.parents) {
      if (visiting.has(parent.checkpoint_id)) {
        fail("checkpoint-parent-cycle", "checkpoint.parents");
      }
      const descriptor = descriptors.get(parent.path);
      const member = members.get(parent.path);
      const parentObject = parsed.get(parent.path) as Checkpoint | undefined;
      if (
        !descriptor ||
        descriptor.role !== "checkpoint" ||
        !member ||
        !parentObject
      ) {
        fail("checkpoint-parent-missing", "checkpoint.parents");
      }
      if (
        parent.digest !== descriptor.digest ||
        parent.digest !== sha256(member.bytes)
      ) {
        fail("reference-digest", "checkpoint.parents");
      }
      if (parentObject.checkpoint_id !== parent.checkpoint_id) {
        fail("checkpoint-parent-missing", "checkpoint.parents");
      }
      visit(parent.path, parentObject);
    }

    visiting.delete(checkpoint.checkpoint_id);
    visited.add(checkpoint.checkpoint_id);
    void path;
  };

  visit(rootPath, root);
}

function verifyCheckpointReferences(
  checkpoint: Checkpoint,
  descriptors: ReadonlyMap<string, ManifestEntry>,
  members: ReadonlyMap<string, LogicalMember>,
  parsed: ReadonlyMap<string, JsonObject>,
): void {
  for (const reference of checkpoint.event_refs) {
    verifyReference(
      reference,
      "event",
      descriptors,
      members,
      "checkpoint.event_refs",
    );
    const event = parsed.get(reference.path);
    if (
      event?.event_id !== reference.event_id ||
      event.session_id !== checkpoint.session_id
    ) {
      fail("reference-digest", "checkpoint.event_refs");
    }
  }

  const gitDescriptor = descriptors.get(checkpoint.git_state.path);
  const gitMember = members.get(checkpoint.git_state.path);
  if (
    !gitDescriptor ||
    gitDescriptor.role !== "git-state" ||
    !gitMember ||
    checkpoint.git_state.digest !== gitDescriptor.digest ||
    checkpoint.git_state.digest !== sha256(gitMember.bytes)
  ) {
    fail("git-state-substitution", "checkpoint.git_state");
  }

  for (const evidence of checkpoint.evidence) {
    if (!evidence.source) continue;
    const descriptor = descriptors.get(evidence.source.path);
    const member = members.get(evidence.source.path);
    const source = parsed.get(evidence.source.path);
    if (
      !descriptor ||
      descriptor.role !== "evidence" ||
      descriptor.media_type !== "application/json" ||
      !member ||
      !source ||
      descriptor.digest !== evidence.source.digest ||
      sha256(member.bytes) !== evidence.source.digest
    ) {
      fail("evidence-source-substitution", "checkpoint.evidence.source");
    }
    for (const identityField of [
      "evidence_id",
      "kind",
      "issuer",
      "subject_digest",
      "result",
      "observed_at",
    ]) {
      if (evidence[identityField] !== source[identityField]) {
        fail("evidence-identity-substitution", "checkpoint.evidence.identity");
      }
    }
  }
}

function verifyReference(
  reference: ObjectReference,
  role: ArchiveEntry["role"],
  descriptors: ReadonlyMap<string, ManifestEntry>,
  members: ReadonlyMap<string, LogicalMember>,
  affectedObject: string,
): void {
  const descriptor = descriptors.get(reference.path);
  const member = members.get(reference.path);
  if (!descriptor || descriptor.role !== role || !member) {
    fail("reference-missing", affectedObject);
  }
  if (
    descriptor.digest !== reference.digest ||
    sha256(member.bytes) !== reference.digest
  ) {
    fail("reference-digest", affectedObject);
  }
}

function collectUntrustedContent(
  entries: readonly ManifestEntry[],
  parsed: ReadonlyMap<string, JsonObject>,
): OracleSuccess["untrustedContent"] {
  const content: Array<{
    source: string;
    value: string;
    executionAllowed: false;
  }> = [];
  for (const entry of entries) {
    const object = parsed.get(entry.path);
    if (!object) continue;
    if (entry.role === "event") {
      const payload = object.payload as JsonObject | undefined;
      const inline = payload?.inline as JsonObject | undefined;
      if (typeof inline?.objective === "string") {
        content.push({
          source: entry.path,
          value: inline.objective,
          executionAllowed: false,
        });
      }
    }
    if (entry.role === "checkpoint") {
      const work = object.work as JsonObject | undefined;
      if (typeof work?.objective === "string") {
        content.push({
          source: entry.path,
          value: work.objective,
          executionAllowed: false,
        });
      }
    }
  }
  return content;
}

function parseSignedObject(
  bytes: Uint8Array,
  limits: OracleLimits,
  affectedObject: string,
): JsonObject {
  try {
    const value = parseJsonSafely(bytes, {
      maxDepth: limits.maxJsonDepth,
      maxStringBytes: limits.maxJsonStringBytes,
    });
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      fail("invalid-json", affectedObject);
    }
    return toPlainJson(value) as JsonObject;
  } catch (error) {
    if (!(error instanceof SafeJsonError)) throw error;
    if (error.kind === "duplicate-key") {
      fail("duplicate-json-key", affectedObject);
    }
    if (error.kind === "resource-limit") {
      if (error.message.includes("nesting")) {
        fail("resource-json-depth", affectedObject);
      }
      fail("resource-json-string", affectedObject);
    }
    fail("invalid-json", affectedObject);
  }
}

function requireEntries(manifest: Manifest): readonly ManifestEntry[] {
  if (!Array.isArray(manifest.entries))
    fail("invalid-schema", "archive.manifest.entries");
  return manifest.entries;
}

function indexMembers(
  members: readonly LogicalMember[],
): ReadonlyMap<string, LogicalMember> {
  return new Map(members.map((member) => [member.logicalPath, member]));
}

function entryObject(index: number, path: string): string {
  return isSafeArchivePath(path)
    ? `archive.entry[${path}]`
    : `manifest.entries[${index}]`;
}

function enforcePositiveLimits(limits: OracleLimits): void {
  for (const value of Object.values(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError("Oracle limits must be positive safe integers.");
    }
  }
}

function fail(
  category: ConstructorParameters<typeof CorpusFailure>[0],
  affectedObject: string,
): never {
  throw new CorpusFailure(category, affectedObject);
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
